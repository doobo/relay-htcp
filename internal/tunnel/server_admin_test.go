package tunnel

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"relay-htcp/internal/config"
)

func newSwapTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := &config.ServerConfig{
		Listen: "127.0.0.1:0",
		Auth: config.AuthConfig{Tokens: []config.Token{
			{Name: "t1", Token: "token-old", Routes: []string{"ssh"}},
		}},
		Routes: []config.Route{{Name: "ssh", Target: "127.0.0.1:1"}},
	}
	cfg.Tunnel.DialTimeout = time.Second
	cfg.Tunnel.IdleTimeout = time.Minute
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewServer(cfg, log)
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// TestServerConfigHotSwap verifies that ApplyConfigYAML swaps tokens and
// routes atomically: the new token works immediately, the old one stops.
func TestServerConfigHotSwap(t *testing.T) {
	s := newSwapTestServer(t)

	dataReq := func(token, route string) int {
		req := httptest.NewRequest(http.MethodPost, DataPath, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Tunnel-Target", route)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		return w.Code
	}

	// Old token works (502 because the target 127.0.0.1:1 is not listening).
	if code := dataReq("token-old", "ssh"); code != http.StatusBadGateway {
		t.Fatalf("old token status = %d, want 502", code)
	}

	const yamlNew = `
listen: "127.0.0.1:0"
auth:
  tokens:
    - name: t2
      token: "token-new"
routes:
  - name: ssh
    target: "127.0.0.1:1"
  - name: mysql
    target: "127.0.0.1:2"
`
	report, err := s.ApplyConfigYAML(yamlNew)
	if err != nil {
		t.Fatal(err)
	}
	if !containsStr(report.Applied, "auth.tokens") || !containsStr(report.Applied, "routes") {
		t.Fatalf("report = %+v", report)
	}

	// Old token is gone.
	if code := dataReq("token-old", "ssh"); code != http.StatusUnauthorized {
		t.Fatalf("old token after swap = %d, want 401", code)
	}
	// New token works, including the newly added route.
	if code := dataReq("token-new", "ssh"); code != http.StatusBadGateway {
		t.Fatalf("new token ssh = %d, want 502", code)
	}
	if code := dataReq("token-new", "mysql"); code != http.StatusBadGateway {
		t.Fatalf("new token mysql = %d, want 502", code)
	}

	// Invalid configs are rejected and not applied.
	if err := s.ValidateConfigYAML("listen: \"\"\n"); err == nil {
		t.Fatal("invalid config accepted by ValidateConfigYAML")
	}
	if _, err := s.ApplyConfigYAML("listen: \"\"\n"); err == nil {
		t.Fatal("invalid config applied")
	}
	if code := dataReq("token-new", "ssh"); code != http.StatusBadGateway {
		t.Fatalf("config changed after failed apply: %d", code)
	}
}

// TestServerApplyConfigKeepsAdminSection verifies that panel saves never
// clobber the file-managed admin section.
func TestServerApplyConfigKeepsAdminSection(t *testing.T) {
	cfg := &config.ServerConfig{
		Listen: "127.0.0.1:0",
		Auth: config.AuthConfig{Tokens: []config.Token{
			{Name: "t1", Token: "token-old"},
		}},
		Routes: []config.Route{{Name: "ssh", Target: "127.0.0.1:1"}},
		Admin:  config.AdminConfig{Enabled: true, Listen: "127.0.0.1:8081", DBPath: "panel.db"},
	}
	cfg.Tunnel.DialTimeout = time.Second
	cfg.Tunnel.IdleTimeout = time.Minute
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewServer(cfg, log)

	// The editable config carries no admin section.
	const y = `
listen: "127.0.0.1:0"
auth:
  tokens:
    - name: t2
      token: "token-new"
routes:
  - name: ssh
    target: "127.0.0.1:2"
`
	if _, err := s.ApplyConfigYAML(y); err != nil {
		t.Fatal(err)
	}
	out := s.CurrentConfigYAML()
	for _, want := range []string{"127.0.0.1:8081", "panel.db", "token-new"} {
		if !strings.Contains(out, want) {
			t.Fatalf("canonical config missing %q:\n%s", want, out)
		}
	}
}

// TestServerStatusReportsLiveStreams checks the status view reflects config
// and (after a stream) the counters.
func TestServerStatusReportsLiveStreams(t *testing.T) {
	s := newSwapTestServer(t)
	st := s.Status()
	if st.Role != "server" || st.Server == nil {
		t.Fatalf("status = %+v", st)
	}
	if st.Server.ActiveTunnels != 0 || len(st.Server.ActiveStreams) != 0 {
		t.Fatalf("initial status = %+v", st.Server)
	}
	if st.Server.DecoyViews < 0 {
		t.Fatal("decoy views negative")
	}
	// A request that is rejected before 200 must not leave a stream behind.
	req := httptest.NewRequest(http.MethodPost, DataPath, nil)
	req.Header.Set("Authorization", "Bearer token-old")
	req.Header.Set("X-Tunnel-Target", "ssh")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	st = s.Status()
	if len(st.Server.ActiveStreams) != 0 {
		t.Fatalf("streams after rejected request = %+v", st.Server.ActiveStreams)
	}
}
