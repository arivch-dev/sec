package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

const (
	kmsURL     = "https://localhost:8443"
	certFile   = "certs/client.crt"
	keyFile    = "certs/client.key"
	caCertFile = "certs/ca.crt"
)

func main() {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to load client cert/key: %v", err)
	}

	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		log.Fatalf("Failed to read CA cert: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{
		Transport: transport,
	}

	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println("============================================================")
	fmt.Println("           KMS Interactive Client")
	fmt.Println("           (Интерактивный клиент KMS)")
	fmt.Println("============================================================")
	fmt.Println()

	for {
		fmt.Println("\nМЕНЮ:")
		fmt.Println("1. Зашифровать данные")
		fmt.Println("2. Расшифровать данные")
		fmt.Println("3. Проверить здоровье KMS")
		fmt.Println("4. Выход")
		fmt.Print("\nВыберите действие (1-4): ")

		scanner.Scan()
		choice := strings.TrimSpace(scanner.Text())

		switch choice {
		case "1":
			encryptData(client, scanner)
		case "2":
			decryptData(client, scanner)
		case "3":
			checkHealth(client)
		case "4":
			fmt.Println("До свидания!")
			return
		default:
			fmt.Println("Неверный выбор, попробуйте снова")
		}
	}
}

func encryptData(client *http.Client, scanner *bufio.Scanner) {
	fmt.Println("\nШИФРОВАНИЕ ДАННЫХ")
	fmt.Println("------------------------------------------------------------")

	fmt.Print("\nВведите данные для шифрования: ")
	scanner.Scan()
	plaintext := scanner.Text()

	if plaintext == "" {
		fmt.Println("Данные не могут быть пустыми")
		return
	}

	fmt.Printf("\nДанные для шифрования: \"%s\"\n", plaintext)
	fmt.Print("Зашифровать эти данные? (да/нет): ")
	scanner.Scan()
	confirm := strings.ToLower(strings.TrimSpace(scanner.Text()))

	if confirm != "да" && confirm != "yes" && confirm != "y" {
		fmt.Println("Шифрование отменено")
		return
	}

	fmt.Println("\nШаг 1: Запрашиваем ключ шифрования (DEK) у KMS...")
	dekResponse, err := client.Get(kmsURL + "/v1/keys/generate-data-key")
	if err != nil {
		fmt.Printf("Ошибка запроса к KMS: %v\n", err)
		return
	}
	defer dekResponse.Body.Close()

	if dekResponse.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(dekResponse.Body)
		fmt.Printf("KMS вернул ошибку (HTTP %d): %s\n", dekResponse.StatusCode, string(body))
		return
	}

	var dekResult struct {
		ID         string `json:"id"`
		Plaintext  string `json:"plaintext"`
		Ciphertext string `json:"ciphertext"`
	}

	if err := json.NewDecoder(dekResponse.Body).Decode(&dekResult); err != nil {
		fmt.Printf("Ошибка чтения ответа: %v\n", err)
		return
	}

	fmt.Println("DEK получен от KMS")
	fmt.Printf("  - ID ключа: %s\n", dekResult.ID)
	fmt.Printf("  - Открытый DEK (будет использован для шифрования): %s...\n", dekResult.Plaintext[:min(20, len(dekResult.Plaintext))])
	fmt.Printf("  - Зашифрованный DEK (будет сохранен в БД KMS): %s...\n", dekResult.Ciphertext[:min(20, len(dekResult.Ciphertext))])

	fmt.Println("\nШаг 2: Шифруем данные локально с помощью DEK...")

	plaintextDEK, err := base64.StdEncoding.DecodeString(dekResult.Plaintext)
	if err != nil {
		fmt.Printf("Ошибка декодирования DEK: %v\n", err)
		return
	}

	encryptedData, err := encryptWithDEK([]byte(plaintext), plaintextDEK)
	if err != nil {
		fmt.Printf("Ошибка шифрования: %v\n", err)
		return
	}

	fmt.Println("\nШИФРОВАНИЕ ЗАВЕРШЕНО!")
	fmt.Println("------------------------------------------------------------")
	fmt.Printf("Исходные данные:      \"%s\"\n", plaintext)
	fmt.Printf("Зашифрованные данные: %s\n", base64.StdEncoding.EncodeToString(encryptedData))
	fmt.Printf("ID ключа:             %s\n", dekResult.ID)
	fmt.Println("------------------------------------------------------------")
	fmt.Println("\nСохраните эти данные в безопасном месте!")
	fmt.Println("  - Зашифрованные данные можно хранить в БД")
	fmt.Println("  - ID ключа нужен для расшифровки")
	fmt.Println("  - Открытый DEK был удален из памяти")
}

func decryptData(client *http.Client, scanner *bufio.Scanner) {
	fmt.Println("\nРАСШИФРОВКА ДАННЫХ")
	fmt.Println("------------------------------------------------------------")

	fmt.Print("\nВведите зашифрованные данные (base64): ")
	scanner.Scan()
	encryptedDataStr := strings.TrimSpace(scanner.Text())

	if encryptedDataStr == "" {
		fmt.Println("Данные не могут быть пустыми")
		return
	}

	fmt.Print("Введите ID ключа (key_id): ")
	scanner.Scan()
	keyID := strings.TrimSpace(scanner.Text())

	if keyID == "" {
		fmt.Println("ID ключа не может быть пустым")
		return
	}

	fmt.Println("\nДанные для расшифровки:")
	fmt.Printf("  - Зашифрованные данные: %s...\n", encryptedDataStr[:min(50, len(encryptedDataStr))])
	fmt.Printf("  - ID ключа:             %s\n", keyID)
	fmt.Print("\nРасшифровать эти данные? (да/нет): ")
	scanner.Scan()
	confirm := strings.ToLower(strings.TrimSpace(scanner.Text()))

	if confirm != "да" && confirm != "yes" && confirm != "y" {
		fmt.Println("Расшифровка отменена")
		return
	}

	fmt.Println("\nШаг 1: Запрашиваем расшифровку DEK у KMS по ID...")

	decryptRequest := map[string]string{
		"id": keyID,
	}
	requestBody, _ := json.Marshal(decryptRequest)

	decryptResponse, err := client.Post(
		kmsURL+"/v1/keys/decrypt",
		"application/json",
		strings.NewReader(string(requestBody)),
	)
	if err != nil {
		fmt.Printf("Ошибка запроса к KMS: %v\n", err)
		return
	}
	defer decryptResponse.Body.Close()

	if decryptResponse.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(decryptResponse.Body)
		fmt.Printf("KMS вернул ошибку (HTTP %d): %s\n", decryptResponse.StatusCode, string(body))
		return
	}

	var decryptResult struct {
		ID        string `json:"id"`
		Plaintext string `json:"plaintext"`
	}

	if err := json.NewDecoder(decryptResponse.Body).Decode(&decryptResult); err != nil {
		fmt.Printf("Ошибка чтения ответа: %v\n", err)
		return
	}

	fmt.Println("DEK расшифрован KMS")
	fmt.Printf("  - ID ключа: %s\n", decryptResult.ID)
	fmt.Printf("  - Открытый DEK: %s...\n", decryptResult.Plaintext[:min(20, len(decryptResult.Plaintext))])

	fmt.Println("\nШаг 2: Расшифровываем данные локально...")

	plaintextDEK, err := base64.StdEncoding.DecodeString(decryptResult.Plaintext)
	if err != nil {
		fmt.Printf("Ошибка декодирования DEK: %v\n", err)
		return
	}

	encryptedData, err := base64.StdEncoding.DecodeString(encryptedDataStr)
	if err != nil {
		fmt.Printf("Ошибка декодирования данных: %v\n", err)
		return
	}

	decryptedData, err := decryptWithDEK(encryptedData, plaintextDEK)
	if err != nil {
		fmt.Printf("Ошибка расшифровки: %v\n", err)
		return
	}

	fmt.Println("\nРАСШИФРОВКА ЗАВЕРШЕНА!")
	fmt.Println("------------------------------------------------------------")
	fmt.Printf("Зашифрованные данные:  %s...\n", encryptedDataStr[:min(50, len(encryptedDataStr))])
	fmt.Printf("Расшифрованные данные: \"%s\"\n", string(decryptedData))
	fmt.Println("------------------------------------------------------------")
}

func checkHealth(client *http.Client) {
	fmt.Println("\nПРОВЕРКА ЗДОРОВЬЯ KMS")
	fmt.Println("------------------------------------------------------------")

	response, err := client.Get(kmsURL + "/health")
	if err != nil {
		fmt.Printf("KMS недоступен: %v\n", err)
		return
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		fmt.Printf("KMS вернул ошибку (HTTP %d)\n", response.StatusCode)
		return
	}

	body, _ := io.ReadAll(response.Body)
	fmt.Printf("KMS работает: %s", string(body))
}

func encryptWithDEK(plaintext, dek []byte) ([]byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return aesGCM.Seal(nonce, nonce, plaintext, nil), nil
}

func decryptWithDEK(ciphertext, dek []byte) ([]byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aesGCM.Open(nil, nonce, ciphertext, nil)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
