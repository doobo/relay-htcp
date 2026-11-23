package tunnel

import (
	"context"
	"io"
	"net"
	"testing"

	"relay-htcp/internal/config"
)

// startGreeter listens on 127.0.0.1:0 and writes "hi" to every connection.
func startGreeter(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("hi"))
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func readGreeting(t *testing.T, conn net.Conn) {
	t.Helper()
	defer conn.Close()
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hi" {
		t.Fatalf("greeting = %q", buf)
	}
}

func TestProviderUseProxyDialsThroughProxy(t *testing.T) {
	target, stopTarget := startGreeter(t)
	defer stopTarget()
	proxyAddr, hits, stopProxy := startHTTPConnectProxy(t)
	defer stopProxy()

	p := &Pool{}
	p.cfg.Store(&config.ClientConfig{Proxy: config.ProxyConfig{
		Enabled: true, Type: config.ProxyHTTP, Address: proxyAddr,
	}})

	conn, err := p.dialProviderLocal(context.Background(), config.Provider{Local: target, UseProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	readGreeting(t, conn)
	if hits.Load() != 1 {
		t.Fatalf("proxy CONNECT hits = %d, want 1", hits.Load())
	}
}

func TestProviderWithoutUseProxyDialsDirect(t *testing.T) {
	target, stopTarget := startGreeter(t)
	defer stopTarget()
	proxyAddr, hits, stopProxy := startHTTPConnectProxy(t)
	defer stopProxy()

	p := &Pool{}
	p.cfg.Store(&config.ClientConfig{Proxy: config.ProxyConfig{
		Enabled: true, Type: config.ProxyHTTP, Address: proxyAddr,
	}})

	conn, err := p.dialProviderLocal(context.Background(), config.Provider{Local: target})
	if err != nil {
		t.Fatal(err)
	}
	readGreeting(t, conn)
	if hits.Load() != 0 {
		t.Fatalf("provider without use_proxy went through the proxy (%d hits)", hits.Load())
	}
}

func TestProviderUseProxyRequiresEnabledProxy(t *testing.T) {
	p := &Pool{}
	p.cfg.Store(&config.ClientConfig{})
	if _, err := p.dialProviderLocal(context.Background(), config.Provider{Local: "127.0.0.1:1", UseProxy: true}); err == nil {
		t.Fatal("use_proxy with proxy disabled dialed without error")
	}
}
