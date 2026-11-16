package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	bcryptCost  = 10
	tokenPrefix = "rhtcp_"
	tokenLength = 40
)

const tokenAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

// HashPassword hashes a cleartext password with bcrypt.
func HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(b), nil
}

// VerifyPassword reports whether password matches a bcrypt hash.
func VerifyPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// SHA256Hex returns the lowercase hex SHA-256 of input. Session tokens are
// stored only as this hash, so the raw token never touches the database.
func SHA256Hex(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}

// RandomToken returns a cryptographically random bearer token
// ("rhtcp_" + 40 lowercase alphanumeric characters).
func RandomToken() (string, error) {
	buf := make([]byte, tokenLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("random token: %w", err)
	}
	out := make([]byte, 0, len(tokenPrefix)+tokenLength)
	out = append(out, tokenPrefix...)
	for _, b := range buf {
		out = append(out, tokenAlphabet[int(b)%len(tokenAlphabet)])
	}
	return string(out), nil
}

// LoginRateLimiter throttles login attempts per client IP: after limit
// failures within window the attempts are rejected until the window rolls
// over. A success clears the bucket.
type LoginRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*loginBucket
	limit   int
	window  time.Duration
}

type loginBucket struct {
	fails int
	reset time.Time
}

// NewLoginRateLimiter builds a limiter with the given per-IP failure limit
// and reset window.
func NewLoginRateLimiter(limit int, window time.Duration) *LoginRateLimiter {
	if limit <= 0 {
		limit = 10
	}
	if window <= 0 {
		window = time.Minute
	}
	return &LoginRateLimiter{buckets: map[string]*loginBucket{}, limit: limit, window: window}
}

// Allow reports whether a login attempt from ip may proceed.
func (rl *LoginRateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b := rl.buckets[ip]
	return b == nil || time.Now().After(b.reset) || b.fails < rl.limit
}

// RecordFailure counts a failed attempt and starts the window on the first.
func (rl *LoginRateLimiter) RecordFailure(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b := rl.buckets[ip]
	if b == nil || time.Now().After(b.reset) {
		rl.buckets[ip] = &loginBucket{fails: 1, reset: time.Now().Add(rl.window)}
		return
	}
	b.fails++
}

// RecordSuccess clears the bucket for ip.
func (rl *LoginRateLimiter) RecordSuccess(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.buckets, ip)
}

// Forget evicts buckets whose window has rolled over.
func (rl *LoginRateLimiter) Forget() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	for ip, b := range rl.buckets {
		if now.After(b.reset) {
			delete(rl.buckets, ip)
		}
	}
}

// clientIP extracts the best-effort client address from a request: the X-
// Forwarded-For first entry when present, else RemoteAddr without the port.
func clientIP(xff, remoteAddr string) string {
	if xff != "" {
		for _, p := range splitComma(xff) {
			if p != "" {
				return p
			}
		}
	}
	return hostPort(remoteAddr)
}
