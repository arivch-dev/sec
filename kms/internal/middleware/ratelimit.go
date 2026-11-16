package middleware

import (
	"log"
	"net/http"
	"sync"

	"golang.org/x/time/rate"
)

type RateLimiter struct {
	mu    sync.RWMutex
	limiters map[string]*rate.Limiter
	r    rate.Limit
	b    int
}

func NewRateLimiter(r rate.Limit, b int) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		r:    r,
		b:    b,
	}
}

func (rl *RateLimiter) getLimiter(clientID string) *rate.Limiter {
	rl.mu.RLock()
	limiter, exists := rl.limiters[clientID]
	rl.mu.RUnlock()

	if exists {
		return limiter
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if limiter, exists := rl.limiters[clientID]; exists {
		return limiter
	}

	limiter = rate.NewLimiter(rl.r, rl.b)
	rl.limiters[clientID] = limiter
	return limiter
}

func ExtractClientCN(r *http.Request) string {
	if r.TLS != nil {
		for _, cert := range r.TLS.PeerCertificates {
			if cert.Subject.CommonName != "" {
				return cert.Subject.CommonName
			}
		}
	}
	return "unknown-client"
}

func (rl *RateLimiter) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID := ExtractClientCN(r)
		limiter := rl.getLimiter(clientID)

		if !limiter.Allow() {
			log.Printf("Rate limit exceeded for client: %s", clientID)
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
