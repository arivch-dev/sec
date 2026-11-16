package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Backend struct {
	URL      *url.URL
	Alive     bool
	Weight    int
	CurrentWeight int
	ActiveConns  int
	FailCount   int
	LatencyMs   int64
	mu      sync.RWMutex
	ReverseProxy *httputil.ReverseProxy
}

func (b *Backend) SetAlive(alive bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.Alive = alive
	if alive {
		b.FailCount = 0
	}
}

func (b *Backend) IsAlive() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.Alive
}

func (b *Backend) IncConns() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ActiveConns++
}

func (b *Backend) DecConns() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ActiveConns--
}

func (b *Backend) GetActiveConns() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.ActiveConns
}

func (b *Backend) GetWeight() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.Weight
}

func (b *Backend) GetLatency() int64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.LatencyMs
}

func (b *Backend) RecordSuccess(durationMs int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.FailCount = 0
	if b.LatencyMs == 0 {
		b.LatencyMs = durationMs
	} else {

		b.LatencyMs = (b.LatencyMs*7 + durationMs*3) / 10
	}
}

func (b *Backend) RecordFailure() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.FailCount++
	if b.FailCount >= 3 && b.Alive {
		b.Alive = false
		log.Printf(" Circuit Breaker: Бэкенд %s переведен в DOWN из-за 3 последовательных сбоев", b.URL)
		return true
	}
	return false
}

type LoadBalancer struct {
	port      string
	backends    []*Backend
	mu       sync.RWMutex
	currentAlgo   string
	roundRobinIndex int
}

var (
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loadbalancer_http_requests_total",
			Help: "Общее количество HTTP запросов",
		},
		[]string{"backend", "status"},
	)

	requestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:  "loadbalancer_request_duration_seconds",
			Help:  "Время обработки запроса в секундах",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"backend"},
	)

	activeConnections = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "loadbalancer_active_connections",
			Help: "Количество активных соединений на бэкенд",
		},
		[]string{"backend"},
	)

	backendHealth = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "loadbalancer_backend_health",
			Help: "Статус здоровья бэкенда (1 - UP, 0 - DOWN)",
		},
		[]string{"backend"},
	)
)

func (lb *LoadBalancer) GetNextPeer() *Backend {
	lb.mu.RLock()
	algorithm := lb.currentAlgo
	lb.mu.RUnlock()

	switch algorithm {
	case "leastconn":
		return lb.getLeastConnectionsPeer()
	case "weighted":
		return lb.getWeightedRoundRobinPeer(false)
	case "adaptive":
		return lb.getWeightedRoundRobinPeer(true)
	default:
		return lb.getRoundRobinPeer()
	}
}

func (lb *LoadBalancer) getRoundRobinPeer() *Backend {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	totalBackends := len(lb.backends)
	if totalBackends == 0 {
		return nil
	}

	for i := 0; i < totalBackends; i++ {
		idx := (lb.roundRobinIndex + i) % totalBackends
		peer := lb.backends[idx]
		if peer.IsAlive() {
			lb.roundRobinIndex = idx + 1
			return peer
		}
	}
	return nil
}

func (lb *LoadBalancer) getLeastConnectionsPeer() *Backend {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	var selected *Backend
	minConns := int(^uint(0) >> 1)

	for _, peer := range lb.backends {
		if peer.IsAlive() {
			conns := peer.GetActiveConns()
			if conns < minConns {
				minConns = conns
				selected = peer
			}
		}
	}
	return selected
}

func (lb *LoadBalancer) getWeightedRoundRobinPeer(adaptive bool) *Backend {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	totalBackends := len(lb.backends)
	if totalBackends == 0 {
		return nil
	}

	totalWeight := 0
	var best *Backend
	bestWeight := -1

	for _, peer := range lb.backends {
		if peer.IsAlive() {
			w := peer.GetWeight()
			if adaptive {

				latency := peer.GetLatency()
				if latency > 0 {
					w = int(1000 / (latency + 10))
					if w < 1 {
						w = 1
					}
				}
			}
			peer.CurrentWeight += w
			totalWeight += w
			if peer.CurrentWeight > bestWeight {
				bestWeight = peer.CurrentWeight
				best = peer
			}
		}
	}

	if best != nil {
		best.CurrentWeight -= totalWeight
	}

	return best
}

func (lb *LoadBalancer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	peer := lb.GetNextPeer()
	if peer == nil {
		http.Error(w, "Service Unavailable: all backends are down", http.StatusServiceUnavailable)
		httpRequestsTotal.WithLabelValues("none", "503").Inc()
		return
	}

	peer.IncConns()
	defer peer.DecConns()

	activeConnections.WithLabelValues(peer.URL.String()).Set(float64(peer.GetActiveConns()))

	recorder := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
	peer.ReverseProxy.ServeHTTP(recorder, r)

	duration := time.Since(start)
	statusCode := fmt.Sprintf("%d", recorder.statusCode)

	httpRequestsTotal.WithLabelValues(peer.URL.String(), statusCode).Inc()
	requestDuration.WithLabelValues(peer.URL.String()).Observe(duration.Seconds())

	if recorder.statusCode >= 200 && recorder.statusCode < 500 {
		peer.RecordSuccess(duration.Milliseconds())
	} else if recorder.statusCode >= 500 {
		if tripped := peer.RecordFailure(); tripped {
			backendHealth.WithLabelValues(peer.URL.String()).Set(0.0)
		}
	}

	log.Printf("Proxy -> %s | Status: %d | Time: %v | Conns: %d", peer.URL, recorder.statusCode, duration, peer.GetActiveConns())
}

type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (rr *responseRecorder) WriteHeader(code int) {
	rr.statusCode = code
	rr.ResponseWriter.WriteHeader(code)
}

func isBackendAlive(u *url.URL) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	healthURL := *u
	healthURL.Path = "/"

	resp, err := client.Get(healthURL.String())
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

func (lb *LoadBalancer) HealthCheck() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		lb.mu.RLock()
		backends := make([]*Backend, len(lb.backends))
		copy(backends, lb.backends)
		lb.mu.RUnlock()

		for _, backend := range backends {
			alive := isBackendAlive(backend.URL)
			backend.SetAlive(alive)

			health := 0.0
			status := "DOWN"
			if alive {
				health = 1.0
				status = "UP"
			}
			backendHealth.WithLabelValues(backend.URL.String()).Set(health)
			log.Printf("HealthCheck: %s is %s", backend.URL, status)
		}
	}
}

func (lb *LoadBalancer) getBackendsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	lb.mu.RLock()
	defer lb.mu.RUnlock()

	type BackendInfo struct {
		URL     string `json:"url"`
		Alive    bool  `json:"alive"`
		Weight   int  `json:"weight"`
		ActiveConns int  `json:"active_connections"`
		LatencyMs  int64 `json:"latency_ms"`
	}

	backends := make([]BackendInfo, len(lb.backends))
	for i, b := range lb.backends {
		backends[i] = BackendInfo{
			URL:     b.URL.String(),
			Alive:    b.IsAlive(),
			Weight:   b.GetWeight(),
			ActiveConns: b.GetActiveConns(),
			LatencyMs:  b.GetLatency(),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"algorithm": lb.currentAlgo,
		"backends": backends,
	})
}

func (lb *LoadBalancer) addBackendHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		URL  string `json:"url"`
		Weight int  `json:"weight"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Weight <= 0 {
		req.Weight = 1
	}

	u, err := url.Parse(req.URL)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid URL: %v", err), http.StatusBadRequest)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(u)
	var newBackend *Backend
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) {
		log.Printf("Proxy error to %s: %v", u, e)
		if newBackend != nil {
			if tripped := newBackend.RecordFailure(); tripped {
				backendHealth.WithLabelValues(u.String()).Set(0.0)
			}
		}
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	newBackend = &Backend{
		URL:     u,
		Alive:    true,
		Weight:    req.Weight,
		ReverseProxy: proxy,
	}

	lb.mu.Lock()
	lb.backends = append(lb.backends, newBackend)
	lb.mu.Unlock()

	log.Printf("Добавлен бэкенд: %s с весом %d", req.URL, req.Weight)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "success",
		"message": fmt.Sprintf("Backend %s added", req.URL),
	})
}

func (lb *LoadBalancer) deleteBackendHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	backendURL := r.URL.Query().Get("url")
	if backendURL == "" {
		http.Error(w, "Missing 'url' parameter", http.StatusBadRequest)
		return
	}

	lb.mu.Lock()
	defer lb.mu.Unlock()

	found := false
	newBackends := make([]*Backend, 0, len(lb.backends))
	for _, b := range lb.backends {
		if b.URL.String() == backendURL {
			found = true
			continue
		}
		newBackends = append(newBackends, b)
	}

	if !found {
		http.Error(w, "Backend not found", http.StatusNotFound)
		return
	}

	lb.backends = newBackends
	log.Printf("Удален бэкенд: %s", backendURL)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "success",
		"message": fmt.Sprintf("Backend %s removed", backendURL),
	})
}

func (lb *LoadBalancer) setAlgorithmHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Algorithm string `json:"algorithm"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	validAlgos := map[string]bool{
		"roundrobin": true,
		"leastconn": true,
		"weighted":  true,
		"adaptive":  true,
	}

	if !validAlgos[req.Algorithm] {
		http.Error(w, "Invalid algorithm. Valid values: roundrobin, leastconn, weighted, adaptive", http.StatusBadRequest)
		return
	}

	lb.mu.Lock()
	lb.currentAlgo = req.Algorithm
	lb.mu.Unlock()

	log.Printf("Алгоритм балансировки изменен на: %s", req.Algorithm)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"algorithm": req.Algorithm,
	})
}

func (lb *LoadBalancer) AddBackend(backendURL string, weight int) {
	u, err := url.Parse(backendURL)
	if err != nil {
		log.Fatalf("Ошибка парсинга URL %s: %v\n", backendURL, err)
	}

	var backend *Backend
	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) {
		log.Printf("Ошибка проксирования на %s: %v", u, e)
		if backend != nil {
			if tripped := backend.RecordFailure(); tripped {
				backendHealth.WithLabelValues(u.String()).Set(0.0)
			}
		}
		http.Error(w, "Backend Error: Gateway failure", http.StatusBadGateway)
	}

	backend = &Backend{
		URL:     u,
		Alive:    true,
		Weight:    weight,
		ReverseProxy: proxy,
	}

	lb.mu.Lock()
	lb.backends = append(lb.backends, backend)
	lb.mu.Unlock()

	log.Printf("Добавлен начальный бэкенд: %s (вес: %d)", backendURL, weight)
}

func main() {
	portFlag := flag.String("port", "8080", "Порт для запуска балансировщика")
	algoFlag := flag.String("algo", "leastconn", "Начальный алгоритм (roundrobin, leastconn, weighted, adaptive)")
	flag.Parse()

	lb := &LoadBalancer{
		port:    *portFlag,
		currentAlgo: *algoFlag,
		backends:  []*Backend{},
	}

	lb.AddBackend("http://127.0.0.1:8081", 1)
	lb.AddBackend("http://127.0.0.1:8082", 2)
	lb.AddBackend("http://127.0.0.1:8083", 1)

	go lb.HealthCheck()

	mux := http.NewServeMux()
	mux.HandleFunc("/", lb.ServeHTTP)
	mux.HandleFunc("/api/backends", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			lb.getBackendsHandler(w, r)
		case http.MethodPost:
			lb.addBackendHandler(w, r)
		case http.MethodDelete:
			lb.deleteBackendHandler(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/algorithm", lb.setAlgorithmHandler)
	mux.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr:       ":" + lb.port,
		Handler:      mux,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   15 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes:  1 << 20,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stop
		log.Println("\nПолучен сигнал завершения. Останавливаем балансировщик...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Ошибка при остановке сервера: %v", err)
		}
	}()

	log.Printf(" Балансировщик нагрузки запущен на порту %s", lb.port)
	log.Printf(" Prometheus метрики: http://localhost:%s/metrics", lb.port)
	log.Printf(" API управления: http://localhost:%s/api/backends", lb.port)
	log.Printf(" Текущий алгоритм: %s", lb.currentAlgo)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Ошибка запуска сервера: %v", err)
	}
	log.Println("Сервер балансировщика успешно завершил работу.")
}
