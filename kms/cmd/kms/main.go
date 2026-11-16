package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"secure-kms/internal/audit"
	"secure-kms/internal/crypto"
	"secure-kms/internal/middleware"
	"secure-kms/internal/storage"

	"golang.org/x/time/rate"
)

var (
	engine  *crypto.CryptoEngine
	store  *storage.Store
	auditLog *audit.Logger
	limiter *middleware.RateLimiter
)

func main() {

	var err error
	if err := os.MkdirAll("./data", 0700); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	store, err = storage.NewStore("./data/kms.db")
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer store.Close()
	log.Println("Database initialized at ./data/kms.db (WAL mode active)")

	auditLog, err = audit.NewLogger("./data/audit.log")
	if err != nil {
		log.Fatalf("Failed to initialize audit logger: %v", err)
	}
	defer auditLog.Close()
	log.Println("Audit logger initialized at ./data/audit.log")

	password := os.Getenv("KMS_MASTER_PASSWORD")
	if password == "" {
		log.Fatal("Error: KMS_MASTER_PASSWORD environment variable is not set")
	}

	engine, err = crypto.NewCryptoEngine(password, "./data/keys")
	if err != nil {
		log.Fatalf("Failed to initialize crypto engine: %v", err)
	}
	log.Printf("Crypto engine initialized. Active master key (KEK) version: %d", engine.GetActiveKEKVersion())

	limiter = middleware.NewRateLimiter(rate.Every(200*time.Millisecond), 10)
	log.Println("Rate limiter initialized: 5 req/sec, burst 10")

	serverCert, err := tls.LoadX509KeyPair("certs/server.crt", "certs/server.key")
	if err != nil {
		log.Fatalf("Failed to load server cert/key: %v", err)
	}

	caCert, err := os.ReadFile("certs/ca.crt")
	if err != nil {
		log.Fatalf("Failed to read CA cert: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:  caCertPool,
		ClientAuth:  tls.RequireAndVerifyClientCert,
		MinVersion:  tls.VersionTLS12,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/v1/keys/generate-data-key", handleGenerateDataKey)
	mux.HandleFunc("/v1/keys/decrypt", handleDecrypt)
	mux.HandleFunc("/v1/admin/rotate-master-key", handleRotateMasterKey)

	protectedMux := limiter.Limit(mux)

	server := &http.Server{
		Addr:       ":8443",
		Handler:      protectedMux,
		TLSConfig:     tlsConfig,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   15 * time.Second,
		IdleTimeout:    60 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stop
		log.Println("\nReceived termination signal. Shutting down KMS gracefully...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Server shutdown error: %v", err)
		}
	}()

	log.Println("Starting Secure KMS on :8443 with mTLS, Persistent KEK Versions, and Audit Logging...")
	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
	log.Println("KMS server stopped.")
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	clientCN := middleware.ExtractClientCN(r)
	auditLog.Log(clientCN, "health_check", "none", "success")

	response := map[string]interface{}{
		"status":   "healthy",
		"kek_version": engine.GetActiveKEKVersion(),
		"rate_limit": "5 req/sec, burst 10",
		"time":    time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleGenerateDataKey(w http.ResponseWriter, r *http.Request) {
	clientCN := middleware.ExtractClientCN(r)
	keyID := "none"
	kekVersion := engine.GetActiveKEKVersion()
	status := "success"

	defer func() {
		auditLog.Log(clientCN, "generate_data_key", keyID, status)
	}()

	plaintextDEK, ciphertextDEK, err := engine.GenerateDataKey()
	if err != nil {
		status = "error: " + err.Error()
		http.Error(w, "Failed to generate data key", http.StatusInternalServerError)
		return
	}

	keyID, err = store.SaveKey(ciphertextDEK, kekVersion, "generated-by-api")
	if err != nil {
		status = "error: " + err.Error()
		http.Error(w, "Failed to save key to database", http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"id":     keyID,
		"plaintext":  base64.StdEncoding.EncodeToString(plaintextDEK),
		"ciphertext": base64.StdEncoding.EncodeToString(ciphertextDEK),
		"kek_version": fmt.Sprintf("%d", kekVersion),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleDecrypt(w http.ResponseWriter, r *http.Request) {
	clientCN := middleware.ExtractClientCN(r)
	keyID := "none"
	status := "success"

	defer func() {
		auditLog.Log(clientCN, "decrypt_data_key", keyID, status)
	}()

	var request struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		status = "error: invalid request"
		http.Error(w, "Invalid request (missing id)", http.StatusBadRequest)
		return
	}

	if request.ID == "" {
		status = "error: missing key id"
		http.Error(w, "Key ID is required", http.StatusBadRequest)
		return
	}

	keyID = request.ID

	ciphertextDEK, kekVersion, err := store.GetKey(request.ID)
	if err != nil {
		status = "error: key not found"
		http.Error(w, "Key not found", http.StatusNotFound)
		return
	}

	plaintextDEK, err := engine.DecryptDataKey(ciphertextDEK, kekVersion)
	if err != nil {
		status = "error: decryption failed"
		http.Error(w, "Failed to decrypt key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"id":     request.ID,
		"plaintext":  base64.StdEncoding.EncodeToString(plaintextDEK),
		"kek_version": fmt.Sprintf("%d", kekVersion),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleRotateMasterKey(w http.ResponseWriter, r *http.Request) {
	clientCN := middleware.ExtractClientCN(r)
	status := "success"

	defer func() {
		auditLog.Log(clientCN, "rotate_master_key", "none", status)
	}()

	if r.Method != http.MethodPost {
		status = "error: method not allowed"
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if clientCN != "admin" && clientCN != "kms-admin" && clientCN != "localhost" {
		status = "error: forbidden (requires admin role)"
		log.Printf("Security alert: Unauthorized key rotation attempt from client CN: %s", clientCN)
		http.Error(w, "Forbidden: Administrator certificate required for KEK rotation", http.StatusForbidden)
		return
	}

	oldVersion := engine.GetActiveKEKVersion()
	newVersion, err := engine.RotateMasterKey()
	if err != nil {
		status = "error: " + err.Error()
		http.Error(w, "Failed to rotate master key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("Master key rotated: v%d -> v%d (persisted to disk)", oldVersion, newVersion)

	response := map[string]interface{}{
		"message":   "Master key rotated successfully and saved to disk",
		"old_version": oldVersion,
		"new_version": newVersion,
		"timestamp":  time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
