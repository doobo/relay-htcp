package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"relay-htcp/internal/admin"
	"relay-htcp/internal/config"
)

const (
	exposeTokenA = "tok-alpha"
	exposeTokenB = "tok-beta"
)

// newExposeServer builds a server with two client tokens that may both use
// the stcp route "pair".
func newExposeServer(t *testing.T) *Server {
	t.Helper()
	cfg := &config.ServerConfig{
		Listen: "127.0.0.1:0",
		Auth: config.AuthConfig{Tokens: []config.Token{
			{Name: "alpha", Token: exposeTokenA},
			{Name: "beta", Token: exposeTokenB},
		}},
		Routes: []config.Route{{Name: "pair", Type: config.RouteTypeSTCP}},
	}
	cfg.Tunnel.DialTimeout = time.Second
	cfg.Tunnel.IdleTimeout = time.Minute
	cfg.Tunnel.STCPTimeout = 5 * time.Second
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return NewServer(cfg, testLogger())
}

// startLabelledProvider queues one provider stream for id. Once paired it
// writes label, then echoes everything it receives.
func startLabelledProvider(ctx context.Context, s *Server, id, label string, echo bool) {
	go func() {
		conn, err := s.stcp.pair(ctx, "pair", TunnelRoleProvider, id, 5*time.Second)
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err := conn.Write([]byte(label)); err != nil {
			return
		}
		if echo {
			_, _ = io.Copy(conn, conn)
		}
	}()
}

func waitQueuedProviders(t *testing.T, s *Server, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for s.stcp.busyProvider("pair") != n {
		if time.Now().After(deadline) {
			t.Fatalf("queued providers = %d, want %d", s.stcp.busyProvider("pair"), n)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRankProvidersStableAndQuotaAware(t *testing.T) {
	s := newExposeServer(t)
	first := s.rankProviders("pair", "10.0.0.7")
	if len(first) != 2 {
		t.Fatalf("ranked = %v, want both tokens", first)
	}
	for i := 0; i < 20; i++ {
		if got := s.rankProviders("pair", "10.0.0.7"); fmt.Sprint(got) != fmt.Sprint(first) {
			t.Fatalf("ranking changed for the same IP: %v vs %v", got, first)
		}
	}

	// Different client IPs must spread over both providers.
	tops := map[string]bool{}
	for i := 1; i <= 40; i++ {
		tops[s.rankProviders("pair", fmt.Sprintf("10.0.1.%d", i))[0]] = true
	}
	if len(tops) != 2 {
		t.Fatalf("40 client IPs mapped to %d provider(s), want 2", len(tops))
	}

	// A quota-blocked provider is skipped.
	blocked := map[string]bool{first[0]: true}
	s.blocked.Store(&blocked)
	if got := s.rankProviders("pair", "10.0.0.7"); len(got) != 1 || got[0] != first[1] {
		t.Fatalf("with %s blocked ranked = %v, want [%s]", first[0], got, first[1])
	}
}

func TestExposedVisitorPrefersRankedProvider(t *testing.T) {
	s := newExposeServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ranked := s.rankProviders("pair", "10.0.0.7")
	labels := map[string]string{
		admin.TokenStatsKey(exposeTokenA): "A",
		admin.TokenStatsKey(exposeTokenB): "B",
	}

	// Both providers online: the top-ranked one wins.
	for _, id := range ranked {
		startLabelledProvider(ctx, s, id, labels[id], false)
	}
	waitQueuedProviders(t, s, 2)
	conn, err := s.stcp.pairExposed(ctx, "pair", ranked, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if got := string(buf); got != labels[ranked[0]] {
		t.Fatalf("paired with %q, want top-ranked %q", got, labels[ranked[0]])
	}
}

func TestExposedVisitorFailsOverWhenTopProviderOffline(t *testing.T) {
	s := newExposeServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ranked := s.rankProviders("pair", "10.0.0.7")
	labels := map[string]string{
		admin.TokenStatsKey(exposeTokenA): "A",
		admin.TokenStatsKey(exposeTokenB): "B",
	}

	// Only the lower-ranked provider is online.
	startLabelledProvider(ctx, s, ranked[1], labels[ranked[1]], false)
	waitQueuedProviders(t, s, 1)
	conn, err := s.stcp.pairExposed(ctx, "pair", ranked, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if got := string(buf); got != labels[ranked[1]] {
		t.Fatalf("paired with %q, want fallback %q", got, labels[ranked[1]])
	}
}

func TestExposedBindFollowsConfigReload(t *testing.T) {
	s := newExposeServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.startSTCPExposure(ctx)

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bind := probe.Addr().String()
	_ = probe.Close()

	withBind := fmt.Sprintf(`
listen: "127.0.0.1:0"
auth:
  tokens:
    - name: alpha
      token: "%s"
routes:
  - name: pair
    type: stcp
    bind: "%s"
`, exposeTokenA, bind)
	if _, err := s.ApplyConfigYAML(withBind); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", bind, 2*time.Second)
	if err != nil {
		t.Fatalf("exposed bind not listening: %v", err)
	}
	_ = conn.Close()

	withoutBind := fmt.Sprintf(`
listen: "127.0.0.1:0"
auth:
  tokens:
    - name: alpha
      token: "%s"
routes:
  - name: pair
    type: stcp
`, exposeTokenA)
	if _, err := s.ApplyConfigYAML(withoutBind); err != nil {
		t.Fatal(err)
	}
	if conn, err := net.DialTimeout("tcp", bind, time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("bind still listening after the route lost its bind address")
	}
}

func TestExposedListenerRelaysToStableProvider(t *testing.T) {
	s := newExposeServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go s.acceptExposed(ctx, "pair", ln)

	ranked := s.rankProviders("pair", "127.0.0.1")
	labels := map[string]string{
		admin.TokenStatsKey(exposeTokenA): "A",
		admin.TokenStatsKey(exposeTokenB): "B",
	}
	for _, id := range ranked {
		startLabelledProvider(ctx, s, id, labels[id], true)
	}
	waitQueuedProviders(t, s, 2)

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if got := string(buf); got != labels[ranked[0]] {
		t.Fatalf("exposed connection reached %q, want %q", got, labels[ranked[0]])
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, 4)
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatal(err)
	}
	if string(echo) != "ping" {
		t.Fatalf("echo = %q", echo)
	}
}
