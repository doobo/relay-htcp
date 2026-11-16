package tunnel

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"relay-htcp/internal/config"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestAuthAndRoutePermission(t *testing.T) {
	cfg := &config.ServerConfig{
		Listen: "127.0.0.1:0",
		Auth: config.AuthConfig{Tokens: []config.Token{
			{Name: "all", Token: "token-all"},
			{Name: "limited", Token: "token-limited", Routes: []string{"ssh"}},
		}},
		Routes: []config.Route{{Name: "ssh", Target: "127.0.0.1:1"}},
	}
	cfg.Tunnel.DialTimeout = time.Second
	cfg.Tunnel.IdleTimeout = time.Minute
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	s := NewServer(cfg, testLogger())

	cases := []struct {
		name   string
		token  string
		route  string
		status int
	}{
		{"no token", "", "ssh", http.StatusUnauthorized},
		{"bad token", "wrong", "ssh", http.StatusUnauthorized},
		{"malformed auth header", "token-all", "ssh", http.StatusUnauthorized},
		{"all token", "token-all", "ssh", http.StatusBadGateway}, // dial of 127.0.0.1:1 fails
		{"limited token allowed", "token-limited", "ssh", http.StatusBadGateway},
		{"limited token denied", "token-limited", "mysql", http.StatusForbidden},
		{"unknown route", "token-all", "mysql", http.StatusNotFound},
		{"missing route header", "token-all", "", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, DataPath, nil)
			if tc.name == "malformed auth header" {
				req.Header.Set("Authorization", tc.token) // no "Bearer " prefix
			} else if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			req.Header.Set("X-Tunnel-Target", tc.route)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d", w.Code, tc.status)
			}
		})
	}
}

func TestHealthEndpoint(t *testing.T) {
	cfg := &config.ServerConfig{
		Listen: "127.0.0.1:0",
		Auth:   config.AuthConfig{Tokens: []config.Token{{Name: "e2e", Token: testToken}}},
		Routes: []config.Route{{Name: "echo", Target: "127.0.0.1:1"}},
	}
	cfg.Tunnel.DialTimeout = time.Second
	cfg.Tunnel.IdleTimeout = time.Minute
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	s := NewServer(cfg, testLogger())

	req := httptest.NewRequest(http.MethodGet, HealthPath, nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if w.Body.String() == "" {
		t.Fatal("empty health body")
	}
}

func TestDisguiseDecoy(t *testing.T) {
	cfg := &config.ServerConfig{
		Listen: "127.0.0.1:0",
		Auth:   config.AuthConfig{Tokens: []config.Token{{Name: "e2e", Token: testToken}}},
		Routes: []config.Route{{Name: "echo", Target: "127.0.0.1:1"}},
	}
	cfg.Tunnel.DialTimeout = time.Second
	cfg.Tunnel.IdleTimeout = time.Minute
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	s := NewServer(cfg, testLogger())

	// Unknown GET path serves the decoy page with a browser-facing header.
	req := httptest.NewRequest(http.MethodGet, "/some/page", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (decoy)", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("content-type = %q, want text/html", got)
	}
}
