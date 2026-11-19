package tunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"relay-htcp/internal/config"
)

const testToken = "e2e-test-token"

// echoTarget starts a local TCP server that replies to every byte with
// "echo:"+bytes.
func echoTarget(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 32*1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(append([]byte("echo:"), buf[:n]...)); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func serverConfigFor(target string) *config.ServerConfig {
	cfg := &config.ServerConfig{
		Listen: "127.0.0.1:0",
		Auth:   config.AuthConfig{Tokens: []config.Token{{Name: "e2e", Token: testToken}}},
		Routes: []config.Route{{Name: "echo", Target: target}},
	}
	cfg.Tunnel.DialTimeout = 5 * time.Second
	cfg.Tunnel.IdleTimeout = time.Minute
	if err := cfg.Validate(); err != nil {
		panic(err)
	}
	return cfg
}

// startTunnelServer starts a tunnel server on a random port and returns its
// scheme-prefixed address plus a stop function.
func startTunnelServer(t *testing.T, target string, useTLS bool) (addr string, stop func()) {
	t.Helper()
	cfg := serverConfigFor(target)
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

// startTunnelClient starts a tunnel client with one local listener and
// returns the bound local address.
func startTunnelClient(t *testing.T, serverAddr string, route string, useTLS bool) (localAddr string, stop func()) {
	t.Helper()
	cfg := &config.ClientConfig{
		Server: serverAddr,
		Auth:   config.ClientAuth{Token: testToken},
		Listeners: []config.Listener{
			{Local: "127.0.0.1:0", Target: route},
		},
	}
	if useTLS {
		cfg.TLS.InsecureSkipVerify = true
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

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := cfg.Listeners[0]
	l.Local = ln.Addr().String()
	go pool.ServeListener(ctx, ln, l)
	return ln.Addr().String(), func() {
		cancel()
		_ = ln.Close()
	}
}

// TestEchoViaURLRouteTarget verifies that route targets may be written as
// http(s):// URLs and are normalized to host:port for the TCP dial.
func TestEchoViaURLRouteTarget(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()
	serverAddr, stopServer := startTunnelServer(t, "http://"+target, false)
	defer stopServer()
	local, stopClient := startTunnelClient(t, serverAddr, "echo", false)
	defer stopClient()
	testEchoRoundTrip(t, local, "url-target")
}

func waitForAddr(t *testing.T, addr string) {
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
	t.Fatalf("server at %s did not come up", addr)
}

// writeSelfSignedCert generates a self-signed certificate valid for
// localhost / 127.0.0.1 and writes PEM files.
func writeSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "relay-htcp-e2e"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// testEchoRoundTrip dials localAddr, writes msg and verifies the echoed
// reply.
func testEchoRoundTrip(t *testing.T, localAddr, msg string) {
	t.Helper()
	conn, err := net.Dial("tcp", localAddr)
	if err != nil {
		t.Fatalf("dial %s: %v", localAddr, err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	want := "echo:" + msg
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != want {
		t.Fatalf("echo = %q, want %q", buf, want)
	}
}

// tryEcho is the non-fatal variant used by the reconnect test.
func tryEcho(localAddr, msg string) (string, error) {
	conn, err := net.Dial("tcp", localAddr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(msg)); err != nil {
		return "", err
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	want := "echo:" + msg
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", err
	}
	if string(buf) != want {
		return string(buf), nil
	}
	return msg, nil
}

// TestE2E_Cleartext verifies the full path over plaintext h2c:
// local conn -> client -> HTTP/2 stream -> server -> target, and back.
func TestE2E_Cleartext(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()
	serverAddr, stopServer := startTunnelServer(t, target, false)
	defer stopServer()
	localAddr, stopClient := startTunnelClient(t, serverAddr, "echo", false)
	defer stopClient()

	testEchoRoundTrip(t, localAddr, "hello h2c")
	// A second connection reuses the tunnel pool.
	testEchoRoundTrip(t, localAddr, "second connection")
}

// TestE2E_TLS verifies the full path over TLS.
func TestE2E_TLS(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()
	serverAddr, stopServer := startTunnelServer(t, target, true)
	defer stopServer()
	localAddr, stopClient := startTunnelClient(t, serverAddr, "echo", true)
	defer stopClient()

	testEchoRoundTrip(t, localAddr, "hello tls")
}

// TestE2E_Reconnect verifies the client re-establishes its tunnel after the
// server restarts on the same port.
func TestE2E_Reconnect(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().String()
	serverAddr := "http://" + port

	srv1 := NewServer(serverConfigFor(target), testLogger())
	ctx1, cancel1 := context.WithCancel(context.Background())
	go srv1.ServeListener(ctx1, ln)
	waitForAddr(t, port)

	localAddr, stopClient := startTunnelClient(t, serverAddr, "echo", false)
	defer stopClient()
	waitForAddr(t, localAddr)
	testEchoRoundTrip(t, localAddr, "before restart")

	// Kill the server; the tunnel dies and the client backs off.
	cancel1()
	srv1.Close()
	_ = ln.Close()

	// Restart a new server on the same port.
	ln2, err := net.Listen("tcp", port)
	if err != nil {
		t.Fatal(err)
	}
	srv2 := NewServer(serverConfigFor(target), testLogger())
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer func() {
		cancel2()
		srv2.Close()
		_ = ln2.Close()
	}()
	go srv2.ServeListener(ctx2, ln2)
	waitForAddr(t, port)

	// The client reconnects with backoff; retry until traffic flows again.
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		got, err := tryEcho(localAddr, "after restart")
		if err == nil && got == "after restart" {
			return
		}
		if err != nil {
			lastErr = err
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("client did not reconnect within deadline: %v", lastErr)
}
