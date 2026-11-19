package tunnel

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"relay-htcp/internal/admin"
	"relay-htcp/internal/config"
)

// TestTokenQuotaBlocksStream verifies the cached quota switch: once a token
// exceeds its daily limit, new data streams are rejected without touching the
// database on the request path.
func TestTokenQuotaBlocksStream(t *testing.T) {
	store, err := admin.Open(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	traffic := admin.NewTrafficStats(store, log)

	cfg := &config.ServerConfig{
		Listen: "127.0.0.1:0",
		Auth: config.AuthConfig{Tokens: []config.Token{{
			Name: "limited", Token: "token-limited", Routes: []string{"ssh"},
			LimitEnabled: true, DailyLimitMB: 1,
		}}},
		Routes: []config.Route{{Name: "ssh", Target: "127.0.0.1:1"}},
	}
	cfg.Tunnel.DialTimeout = time.Second
	cfg.Tunnel.IdleTimeout = time.Minute
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	s := NewServer(cfg, log)
	s.SetTraffic(traffic)

	// Under the limit: the request proceeds to the target dial (502).
	req := func() int {
		r := httptest.NewRequest(http.MethodPost, DataPath, nil)
		r.Header.Set("Authorization", "Bearer token-limited")
		r.Header.Set("X-Tunnel-Target", "ssh")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w.Code
	}
	s.refreshTokenLimits()
	if code := req(); code != http.StatusBadGateway {
		t.Fatalf("under limit = %d, want 502", code)
	}

	// Record 2 MiB against a 1 MiB daily limit, then refresh the cache.
	key := admin.TokenStatsKey("token-limited")
	traffic.Record(admin.TrafficScopeServer, key, "", "ssh", 2<<20, 0)
	s.refreshTokenLimits()
	if !s.TokenBlocked(key) {
		t.Fatal("token not blocked after exceeding its daily limit")
	}
	if code := req(); code != http.StatusTooManyRequests {
		t.Fatalf("over limit = %d, want 429", code)
	}

	// Turning the limit off clears the cached block on the next refresh.
	off := `
listen: "127.0.0.1:0"
auth:
  tokens:
    - name: limited
      token: "token-limited"
      routes: [ssh]
      limit_enabled: false
routes:
  - name: ssh
    target: "127.0.0.1:1"
`
	if _, err := s.ApplyConfigYAML(off); err != nil {
		t.Fatal(err)
	}
	if s.TokenBlocked(key) {
		t.Fatal("token still blocked after disabling limits")
	}
	if code := req(); code != http.StatusBadGateway {
		t.Fatalf("after unblock = %d, want 502", code)
	}
}
