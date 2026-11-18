package tunnel

import (
	"context"
	"net"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"

	"relay-htcp/internal/config"
)

func startXHTTPClient(t *testing.T, serverAddr string, tlsSkip bool, xhttpPath string) (localAddr string, stop func()) {
	localAddr, _, stop = startXHTTPClientPool(t, serverAddr, tlsSkip, xhttpPath)
	return localAddr, stop
}

func startXHTTPClientPool(t *testing.T, serverAddr string, tlsSkip bool, xhttpPath string) (localAddr string, pool *Pool, stop func()) {
	t.Helper()
	cfg := &config.ClientConfig{
		Auth: config.ClientAuth{Token: testToken},
		Servers: []config.ServerEndpoint{{
			Name: "xhttp", URL: serverAddr, Transport: config.TransportXHTTP,
			XHTTPPath: xhttpPath,
		}},
		Listeners: []config.Listener{{
			Local: "127.0.0.1:0", Target: "echo",
			Servers: []string{"xhttp"}, Strategy: config.StrategyFailover,
		}},
	}
	cfg.TLS.InsecureSkipVerify = tlsSkip
	cfg.Tunnel.Connections = 1
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

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	l := cfg.Listeners[0]
	l.Local = ln.Addr().String()
	go pool.ServeListener(ctx, ln, l)
	return ln.Addr().String(), pool, func() {
		cancel()
		_ = ln.Close()
	}
}

// TestXHTTPEchoH2C verifies the split upload/download transport against a
// cleartext HTTP/2 server.
func TestXHTTPEchoH2C(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()
	serverAddr, stopServer := startTunnelServer(t, target, false)
	defer stopServer()

	local, stop := startXHTTPClient(t, serverAddr, false, "")
	defer stop()
	testEchoRoundTrip(t, local, "xhttp-h2c")
}

// TestXHTTPEchoTLS verifies the same transport over TLS, which is what a CDN
// or Cloudflare edge uses.
func TestXHTTPEchoTLS(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()
	serverAddr, stopServer := startTunnelServer(t, target, true)
	defer stopServer()

	local, stop := startXHTTPClient(t, serverAddr, true, "")
	defer stop()
	testEchoRoundTrip(t, local, "xhttp-tls")
}

// TestXHTTPThroughHTTP1Proxy verifies the transport through a TLS-terminating
// HTTP/1.1 reverse proxy that streams responses. This is the shape used by
// Nginx in front of the origin (and approximates a CDN): uploads are complete
// POSTs and the download is a streaming response.
func TestXHTTPThroughHTTP1Proxy(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()
	serverAddr, stopServer := startTunnelServer(t, target, false)
	defer stopServer()

	upstream, err := url.Parse(serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.FlushInterval = -1
	front := httptest.NewTLSServer(proxy)
	defer front.Close()

	local, stop := startXHTTPClient(t, front.URL, true, "")
	defer stop()
	testEchoRoundTrip(t, local, "xhttp-proxy")
}

// TestXHTTPCustomPath verifies that the endpoint prefix can be changed, which
// is needed when another service already owns /xhttp on the same domain.
func TestXHTTPCustomPath(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()

	cfg := serverConfigFor(target)
	cfg.Tunnel.XHTTPPath = "/custom"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(cfg, testLogger())
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.ServeListener(ctx, ln)
	waitForAddr(t, ln.Addr().String())
	defer func() {
		cancel()
		srv.Close()
		_ = ln.Close()
	}()

	serverAddr := "http://" + ln.Addr().String()
	local, stop := startXHTTPClient(t, serverAddr, false, "/custom")
	defer stop()
	testEchoRoundTrip(t, local, "xhttp-custom-path")
}
