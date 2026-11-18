package tunnel

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"relay-htcp/internal/config"
)

// startHotClient starts a pool using the listener-registry API (StartListeners).
func startHotClient(t *testing.T, serverAddr string, listeners []config.Listener) (*Pool, func()) {
	t.Helper()
	cfg := &config.ClientConfig{
		Server:    serverAddr,
		Auth:      config.ClientAuth{Token: testToken},
		Listeners: listeners,
	}
	cfg.Tunnel.Connections = 2
	cfg.Tunnel.Heartbeat = 2 * time.Second
	cfg.Tunnel.HeartbeatMiss = 3
	cfg.Tunnel.ReconnectMin = 200 * time.Millisecond
	cfg.Tunnel.ReconnectMax = 2 * time.Second
	cfg.Tunnel.StreamTimeout = 15 * time.Second
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	pool, err := NewPool(cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	pool.Start(ctx)
	if err := pool.StartListeners(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	return pool, func() {
		pool.StopAllListeners()
		cancel()
	}
}

func freeLocalAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// boundAddr returns the registered listener's actual bound address, waiting
// for it to accept.
func boundAddr(t *testing.T, p *Pool, local string) string {
	t.Helper()
	ls := p.listenerFor(local)
	if ls == nil {
		t.Fatalf("listener %s not registered", local)
	}
	waitForAddr(t, ls.ln.Addr().String())
	return ls.ln.Addr().String()
}

func clientListenerCount(p *Pool) int {
	return len(p.Status().Client.Listeners)
}

func applyClientYAML(t *testing.T, p *Pool, serverAddr string, listeners ...[2]string) {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "server: %q\n", serverAddr)
	fmt.Fprintf(&b, "auth:\n  token: %q\n", testToken)
	b.WriteString("listeners:\n")
	for _, l := range listeners {
		fmt.Fprintf(&b, "  - local: %q\n    target: %q\n", l[0], l[1])
	}
	if _, err := p.ApplyConfigYAML(b.String()); err != nil {
		t.Fatal(err)
	}
}

func dialOK(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("dial %s: no connect in 3s", addr)
}

func dialRefusedEventually(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			return
		}
		_ = c.Close()
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("dial %s: still accepting after listener stop", addr)
}

// TestPoolListenerHotApply verifies that ApplyConfigYAML adds, removes and
// retargets local listeners live, and that a hot-added listener carries
// real traffic end to end.
func TestPoolListenerHotApply(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()
	serverAddr, stopServer := startTunnelServer(t, target, false)
	defer stopServer()

	const route = "echo" // server-side route name, not an address
	l1 := freeLocalAddr(t)
	l2 := freeLocalAddr(t)
	pool, stop := startHotClient(t, serverAddr, []config.Listener{{Local: l1, Target: route}})
	defer stop()

	if n := clientListenerCount(pool); n != 1 {
		t.Fatalf("initial listeners = %d, want 1", n)
	}
	a1 := boundAddr(t, pool, l1)
	testEchoRoundTrip(t, a1, "hello")

	// Add l2; both must serve.
	applyClientYAML(t, pool, serverAddr, [2]string{l1, route}, [2]string{l2, route})
	if n := clientListenerCount(pool); n != 2 {
		t.Fatalf("after add = %d, want 2", n)
	}
	testEchoRoundTrip(t, boundAddr(t, pool, l2), "via-hot-listener")
	testEchoRoundTrip(t, a1, "still-working")

	// Remove l1; its port must stop accepting.
	applyClientYAML(t, pool, serverAddr, [2]string{l2, route})
	if n := clientListenerCount(pool); n != 1 {
		t.Fatalf("after remove = %d, want 1", n)
	}
	dialRefusedEventually(t, a1)
	testEchoRoundTrip(t, boundAddr(t, pool, l2), "l2-only")

	// Retarget l2: the registry must reflect the new target.
	applyClientYAML(t, pool, serverAddr, [2]string{l2, "127.0.0.1:1"})
	st := pool.Status()
	if len(st.Client.Listeners) != 1 || st.Client.Listeners[0].Target != "127.0.0.1:1" {
		t.Fatalf("retarget = %+v", st.Client.Listeners)
	}

	// Invalid config (missing token) is rejected, listeners untouched.
	if err := pool.ValidateConfigYAML("server: " + serverAddr + "\n"); err == nil {
		t.Fatal("config without token accepted")
	}
	if n := clientListenerCount(pool); n != 1 {
		t.Fatalf("listener count changed by failed apply = %d", n)
	}
}

// TestPoolApplyConfigKeepsAdminSection verifies that panel saves never
// clobber the file-managed admin section.
func TestPoolApplyConfigKeepsAdminSection(t *testing.T) {
	l1 := freeLocalAddr(t)
	cfg := &config.ClientConfig{
		Server:  "http://127.0.0.1:1",
		Auth:    config.ClientAuth{Token: testToken},
		Listeners: []config.Listener{{Local: l1, Target: "echo"}},
		Admin:   config.AdminConfig{Enabled: true, Listen: "127.0.0.1:15630"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	pool, err := NewPool(cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool.Start(ctx)
	defer pool.StopAllListeners()

	applyClientYAML(t, pool, "http://127.0.0.1:1", [2]string{l1, "echo"})
	if out := pool.CurrentConfigYAML(); !strings.Contains(out, "127.0.0.1:15630") {
		t.Fatalf("admin section clobbered by apply:\n%s", out)
	}
}
