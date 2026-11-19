package tunnel

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"relay-htcp/internal/config"
)

// startHTTPConnectProxy is a minimal HTTP CONNECT proxy for tests.
func startHTTPConnectProxy(t *testing.T) (addr string, hits *atomic.Int64, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hits = &atomic.Int64{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					_, _ = io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
					return
				}
				target, err := net.DialTimeout("tcp", req.Host, 5*time.Second)
				if err != nil {
					_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				hits.Add(1)
				defer target.Close()
				_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
				go func() {
					_, _ = io.Copy(target, br)
					_ = target.Close()
				}()
				_, _ = io.Copy(c, target)
			}(conn)
		}
	}()
	return ln.Addr().String(), hits, func() { _ = ln.Close() }
}

// startSOCKS5Proxy is a minimal no-auth SOCKS5 CONNECT proxy for tests.
func startSOCKS5Proxy(t *testing.T) (addr string, hits *atomic.Int64, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hits = &atomic.Int64{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = socks5Serve(c, func() { hits.Add(1) })
			}(conn)
		}
	}()
	return ln.Addr().String(), hits, func() { _ = ln.Close() }
}

func socks5Serve(c net.Conn, onConnect func()) error {
	br := bufio.NewReader(c)
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil {
		return err
	}
	if head[0] != 5 {
		return fmt.Errorf("socks version %d", head[0])
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return err
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return err
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return err
	}
	if req[0] != 5 || req[1] != 1 { // CONNECT
		return fmt.Errorf("unsupported request")
	}
	var host string
	switch req[3] {
	case 1:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(br, ip); err != nil {
			return err
		}
		host = net.IP(ip).String()
	case 3:
		n, err := br.ReadByte()
		if err != nil {
			return err
		}
		name := make([]byte, int(n))
		if _, err := io.ReadFull(br, name); err != nil {
			return err
		}
		host = string(name)
	case 4:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(br, ip); err != nil {
			return err
		}
		host = net.IP(ip).String()
	default:
		return fmt.Errorf("bad atyp %d", req[3])
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(br, portBuf); err != nil {
		return err
	}
	port := binary.BigEndian.Uint16(portBuf)
	target, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))), 5*time.Second)
	if err != nil {
		_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return err
	}
	defer target.Close()
	if onConnect != nil {
		onConnect()
	}
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	go func() {
		_, _ = io.Copy(target, br)
		_ = target.Close()
	}()
	_, _ = io.Copy(c, target)
	return nil
}

func TestServerRouteProxyHTTP(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()
	proxyAddr, hits, stopProxy := startHTTPConnectProxy(t)
	defer stopProxy()

	cfg := &config.ServerConfig{
		Listen: "127.0.0.1:0",
		Auth:   config.AuthConfig{Tokens: []config.Token{{Name: "t", Token: "token"}}},
		Routes: []config.Route{
			{Name: "direct", Target: target},
			{Name: "proxied", Target: target, UseProxy: true},
		},
		Proxy: config.ProxyConfig{Enabled: true, Type: config.ProxyHTTP, Address: proxyAddr},
	}
	cfg.Tunnel.DialTimeout = 5 * time.Second
	cfg.Tunnel.IdleTimeout = time.Minute
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	s := NewServer(cfg, testLogger())

	roundTrip := func(route string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := s.dialRoute(ctx, cfg, route, target)
		if err != nil {
			t.Fatalf("dial %s: %v", route, err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("hi")); err != nil {
			t.Fatalf("write %s: %v", route, err)
		}
		buf := make([]byte, 16)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read %s: %v", route, err)
		}
		if got := string(buf[:n]); got != "echo:hi" {
			t.Fatalf("%s response = %q", route, got)
		}
	}

	roundTrip("proxied")
	if hits.Load() != 1 {
		t.Fatalf("proxy hits = %d, want 1", hits.Load())
	}
	roundTrip("direct")
	if hits.Load() != 1 {
		t.Fatalf("direct route used the proxy: hits = %d", hits.Load())
	}
}

func TestServerRouteProxySOCKS5(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()
	proxyAddr, hits, stopProxy := startSOCKS5Proxy(t)
	defer stopProxy()

	cfg := &config.ServerConfig{
		Listen: "127.0.0.1:0",
		Auth:   config.AuthConfig{Tokens: []config.Token{{Name: "t", Token: "token"}}},
		Routes: []config.Route{{Name: "proxied", Target: target, UseProxy: true}},
		Proxy:  config.ProxyConfig{Enabled: true, Type: config.ProxySOCKS5, Address: proxyAddr},
	}
	cfg.Tunnel.DialTimeout = 5 * time.Second
	cfg.Tunnel.IdleTimeout = time.Minute
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	s := NewServer(cfg, testLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := s.dialRoute(ctx, cfg, "proxied", target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("socks")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "echo:socks" {
		t.Fatalf("response = %q", got)
	}
	if hits.Load() != 1 {
		t.Fatalf("proxy hits = %d, want 1", hits.Load())
	}
}

func TestServerRouteProxyDisabledStaysDirect(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()

	cfg := &config.ServerConfig{
		Listen: "127.0.0.1:0",
		Auth:   config.AuthConfig{Tokens: []config.Token{{Name: "t", Token: "token"}}},
		Routes: []config.Route{{Name: "r", Target: target, UseProxy: true}},
		// UseProxy is set, but the global proxy is disabled, so dialing must
		// still reach the target directly.
		Proxy: config.ProxyConfig{Enabled: false, Address: "127.0.0.1:1"},
	}
	cfg.Tunnel.DialTimeout = 5 * time.Second
	cfg.Tunnel.IdleTimeout = time.Minute
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	s := NewServer(cfg, testLogger())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := s.dialRoute(ctx, cfg, "r", target)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

func startClientWithProxy(t *testing.T, serverAddr string, tlsSkip bool, proxy config.ClientProxy) (localAddr string, stop func()) {
	t.Helper()
	cfg := &config.ClientConfig{
		Auth: config.ClientAuth{Token: testToken},
		Servers: []config.ServerEndpoint{{
			Name: "proxy", URL: serverAddr, Transport: config.TransportHTTP,
		}},
		Proxy: proxy,
		Listeners: []config.Listener{{
			Local: "127.0.0.1:0", Target: "echo",
			Servers: []string{"proxy"}, Strategy: config.StrategyFailover,
		}},
	}
	cfg.TLS.InsecureSkipVerify = tlsSkip
	cfg.Tunnel.Connections = 1
	cfg.Tunnel.Heartbeat = 2 * time.Second
	cfg.Tunnel.HeartbeatMiss = 3
	cfg.Tunnel.ReconnectMin = 200 * time.Millisecond
	cfg.Tunnel.ReconnectMax = 2 * time.Second
	cfg.Tunnel.StreamTimeout = 10 * time.Second
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
		cancel()
		_ = ln.Close()
	}
}

func TestClientHTTPProxy(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()
	serverAddr, stopServer := startTunnelServer(t, target, true)
	defer stopServer()
	proxyAddr, hits, stopProxy := startHTTPConnectProxy(t)
	defer stopProxy()

	local, stop := startClientWithProxy(t, serverAddr, true, config.ClientProxy{
		Enabled: true, Type: config.ProxyHTTP, Address: proxyAddr,
	})
	defer stop()
	testEchoRoundTrip(t, local, "via-http-proxy")
	if hits.Load() == 0 {
		t.Fatal("HTTP proxy received no CONNECT request")
	}
}

func TestClientSOCKS5Proxy(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()
	serverAddr, stopServer := startTunnelServer(t, target, false)
	defer stopServer()
	proxyAddr, hits, stopProxy := startSOCKS5Proxy(t)
	defer stopProxy()

	local, stop := startClientWithProxy(t, serverAddr, false, config.ClientProxy{
		Enabled: true, Type: config.ProxySOCKS5, Address: proxyAddr,
	})
	defer stop()
	testEchoRoundTrip(t, local, "via-socks5")
	if hits.Load() == 0 {
		t.Fatal("SOCKS5 proxy received no CONNECT request")
	}
}
