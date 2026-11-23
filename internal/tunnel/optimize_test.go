package tunnel

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"relay-htcp/internal/config"
)

func TestAuthenticateUsesTokenIndex(t *testing.T) {
	cfg := &config.ServerConfig{
		Listen: "127.0.0.1:0",
		Auth: config.AuthConfig{Tokens: []config.Token{
			{Name: "alpha", Token: "token-alpha"},
			{Name: "beta", Token: "token-beta"},
		}},
		Routes: []config.Route{{Name: "ssh", Target: "127.0.0.1:1"}},
	}
	cfg.Tunnel.DialTimeout = time.Second
	cfg.Tunnel.IdleTimeout = time.Minute
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	s := NewServer(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	check := func(header string, want string) {
		t.Helper()
		r := httptest.NewRequest("POST", DataPath, nil)
		if header != "" {
			r.Header.Set("Authorization", header)
		}
		entry, ok := s.authenticate(r)
		if want == "" {
			if ok {
				t.Fatalf("authenticate(%q) accepted, want reject", header)
			}
			return
		}
		if !ok || entry.name != want {
			t.Fatalf("authenticate(%q) = %v, %v; want %s", header, entry, ok, want)
		}
	}
	check("Bearer token-alpha", "alpha")
	check("Bearer token-beta", "beta")
	check("Bearer token-gamma", "")
	check("Bearer token-alph", "")
	check("Bearer ", "")
	check("", "")

	if _, err := s.ApplyConfigYAML(`
listen: "127.0.0.1:0"
auth:
  tokens:
    - name: gamma
      token: "token-gamma"
routes:
  - name: ssh
    target: "127.0.0.1:1"
`); err != nil {
		t.Fatal(err)
	}
	check("Bearer token-alpha", "")
	check("Bearer token-gamma", "gamma")
}

func TestPoolChangeBroadcastWakesAllWaiters(t *testing.T) {
	p := &Pool{changeCh: make(chan struct{})}
	first, second := p.changed(), p.changed()
	p.signalChange()
	for i, ch := range []<-chan struct{}{first, second} {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatalf("waiter %d was not woken", i)
		}
	}
	if p.changed() == first {
		t.Fatal("change channel was not replaced")
	}
}
