package tunnel

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"relay-htcp/internal/config"
)

// stcpServerConfig builds a server with one stcp route and one tcp route.
func stcpServerConfig(timeout time.Duration) *config.ServerConfig {
	cfg := &config.ServerConfig{
		Listen: "127.0.0.1:0",
		Auth:   config.AuthConfig{Tokens: []config.Token{{Name: "stcp", Token: testToken}}},
		Routes: []config.Route{
			{Name: "pair", Type: config.RouteTypeSTCP},
			{Name: "echo", Target: "127.0.0.1:1"},
		},
	}
	cfg.Tunnel.DialTimeout = 5 * time.Second
	cfg.Tunnel.IdleTimeout = time.Minute
	cfg.Tunnel.STCPTimeout = timeout
	if err := cfg.Validate(); err != nil {
		panic(err)
	}
	return cfg
}

// startSTCPServer starts a tunnel server with an stcp route.
func startSTCPServer(t *testing.T, timeout time.Duration, useTLS bool) (addr string, stop func()) {
	t.Helper()
	cfg := stcpServerConfig(timeout)
	if useTLS {
		certFile, keyFile := writeSelfSignedCert(t)
		cfg.TLS = config.TLSConfig{Cert: certFile, Key: keyFile}
	}
	srv := NewServer(cfg, testLogger())
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go srv.ServeListener(ctx, ln)
	waitForAddr(t, ln.Addr().String())
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	return scheme + "://" + ln.Addr().String(), func() {
		cancel()
		srv.Close()
		_ = ln.Close()
	}
}

func stcpClientConfig(serverAddr, transport string, useTLS bool) *config.ClientConfig {
	cfg := &config.ClientConfig{
		Auth: config.ClientAuth{Token: testToken},
		Servers: []config.ServerEndpoint{{
			Name: "srv", URL: serverAddr, Transport: transport,
		}},
	}
	if useTLS {
		cfg.TLS.InsecureSkipVerify = true
	}
	cfg.Tunnel.Connections = 1
	cfg.Tunnel.Heartbeat = 2 * time.Second
	cfg.Tunnel.HeartbeatMiss = 3
	cfg.Tunnel.ReconnectMin = 200 * time.Millisecond
	cfg.Tunnel.ReconnectMax = 2 * time.Second
	cfg.Tunnel.StreamTimeout = 15 * time.Second
	return cfg
}

// startSTCPProvider runs a provider client for route, exposing local.
func startSTCPProvider(t *testing.T, serverAddr, transport, route, local string) (stop func()) {
	t.Helper()
	cfg := stcpClientConfig(serverAddr, transport, strings.HasPrefix(serverAddr, "https://"))
	cfg.Providers = []config.Provider{{
		Route: route, Local: local, Servers: []string{"srv"}, Pool: 2,
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	pool, err := NewPool(cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	pool.Start(ctx)
	if err := pool.StartProviders(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	return func() {
		pool.StopAllProviders()
		cancel()
	}
}

// startSTCPVisitor runs a visitor client: a local listener mapped to route.
func startSTCPVisitor(t *testing.T, serverAddr, transport, route string) (localAddr string, stop func()) {
	t.Helper()
	cfg := stcpClientConfig(serverAddr, transport, strings.HasPrefix(serverAddr, "https://"))
	cfg.Listeners = []config.Listener{{
		Local: "127.0.0.1:0", Target: route, Servers: []string{"srv"},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	pool, err := NewPool(cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	pool.Start(ctx)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	l := cfg.Listeners[0]
	l.Local = ln.Addr().String()
	go pool.ServeListener(ctx, ln, l)
	return ln.Addr().String(), func() {
		_ = ln.Close()
		cancel()
	}
}

// testSTCPEcho retries until a provider warm stream has reached the server,
// then checks two sequential sessions (which must each consume a stream).
func testSTCPEcho(t *testing.T, localAddr string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("tcp", localAddr)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		_, _ = conn.Write([]byte("first"))
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, len("echo:first"))
		_, rerr := io.ReadFull(conn, buf)
		_ = conn.Close()
		if rerr == nil && string(buf) == "echo:first" {
			testEchoRoundTrip(t, localAddr, "second")
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("stcp echo did not become ready")
}

func TestSTCPEchoH2C(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()

	serverAddr, stopServer := startSTCPServer(t, 5*time.Second, false)
	defer stopServer()
	stopProvider := startSTCPProvider(t, serverAddr, config.TransportHTTP, "pair", target)
	defer stopProvider()
	local, stopVisitor := startSTCPVisitor(t, serverAddr, config.TransportHTTP, "pair")
	defer stopVisitor()

	testSTCPEcho(t, local)
}

func TestSTCPEchoXHTTP(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()

	serverAddr, stopServer := startSTCPServer(t, 5*time.Second, false)
	defer stopServer()
	stopProvider := startSTCPProvider(t, serverAddr, config.TransportXHTTP, "pair", target)
	defer stopProvider()
	local, stopVisitor := startSTCPVisitor(t, serverAddr, config.TransportXHTTP, "pair")
	defer stopVisitor()

	testSTCPEcho(t, local)
}

func TestSTCPEchoTLS(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()

	serverAddr, stopServer := startSTCPServer(t, 5*time.Second, true)
	defer stopServer()
	stopProvider := startSTCPProvider(t, serverAddr, config.TransportXHTTP, "pair", target)
	defer stopProvider()
	local, stopVisitor := startSTCPVisitor(t, serverAddr, config.TransportXHTTP, "pair")
	defer stopVisitor()

	testSTCPEcho(t, local)
}

// TestSTCPVisitorWithoutProvider verifies the visitor gets a clean 503 when no
// provider is queued, and that the pairing timeout bounds the wait.
func TestSTCPVisitorWithoutProvider(t *testing.T) {
	serverAddr, stopServer := startSTCPServer(t, 200*time.Millisecond, false)
	defer stopServer()

	req, err := http.NewRequest(http.MethodPost, serverAddr+DataPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-Tunnel-Target", "pair")
	req.Header.Set(TunnelRoleHeader, TunnelRoleProvider)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("idle provider status = %d, want 204", resp.StatusCode)
	}

	req, err = http.NewRequest(http.MethodPost, serverAddr+DataPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-Tunnel-Target", "pair")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("visitor without provider status = %d, want 503", resp.StatusCode)
	}
}

// TestSTCPProviderRoleOnTCPRoute rejects a provider stream aimed at a normal
// tcp route instead of pairing it with a visitor.
func TestSTCPProviderRoleOnTCPRoute(t *testing.T) {
	serverAddr, stopServer := startSTCPServer(t, time.Second, false)
	defer stopServer()

	req, err := http.NewRequest(http.MethodPost, serverAddr+DataPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-Tunnel-Target", "echo")
	req.Header.Set(TunnelRoleHeader, TunnelRoleProvider)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("provider on tcp route status = %d, want 400", resp.StatusCode)
	}
}
