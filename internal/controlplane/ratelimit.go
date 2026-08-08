package controlplane

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (a *App) sessionRedisKey(token string) string {
	mac := hmac.New(sha256.New, a.config.SessionSecret)
	_, _ = mac.Write([]byte(token))
	return "session:" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (a *App) rateLimit(scope string, limit int64, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mac := hmac.New(sha256.New, a.config.SessionSecret)
			_, _ = mac.Write([]byte(scope + "\x00" + clientIP(r)))
			key := "rate:" + scope + ":" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
			pipe := a.redis.TxPipeline()
			count := pipe.Incr(r.Context(), key)
			pipe.ExpireNX(r.Context(), key, window)
			if _, err := pipe.Exec(r.Context()); err == nil && count.Val() > limit {
				w.Header().Set("Retry-After", strconv.Itoa(int(window.Seconds())))
				problem(w, http.StatusTooManyRequests, "rate-limit", "Слишком много запросов", "Повторите попытку позже.")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func clientIP(r *http.Request) string {
	if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); forwarded != "" {
		return forwarded
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
