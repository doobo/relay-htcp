package tunnel

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	xproxy "golang.org/x/net/proxy"

	"relay-htcp/internal/config"
)

// dialRoute opens a TCP connection to a route target. Routes that opt into
// use_proxy go through the server-wide HTTP/SOCKS5 proxy; every other route
// dials the target directly.
func (s *Server) dialRoute(ctx context.Context, cfg *config.ServerConfig, route, dest string) (net.Conn, error) {
	timeout := cfg.Tunnel.DialTimeout
	if cfg.Proxy.Enabled && cfg.RouteUsesProxy(route) {
		conn, err := dialViaProxy(ctx, cfg.Proxy, dest, timeout)
		if err != nil {
			return nil, fmt.Errorf("proxy %s -> %s: %w", cfg.Proxy.Address, dest, err)
		}
		return conn, nil
	}
	return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", dest)
}

func dialViaProxy(ctx context.Context, p config.ProxyConfig, dest string, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	switch p.Type {
	case config.ProxySOCKS5, "socks5h", "socks":
		return dialSOCKS5(ctx, p, dest, timeout)
	case config.ProxyHTTP, "https", "":
		return dialHTTPProxy(ctx, p, dest, timeout)
	default:
		return nil, fmt.Errorf("unsupported proxy type %q", p.Type)
	}
}

func dialSOCKS5(ctx context.Context, p config.ProxyConfig, dest string, timeout time.Duration) (net.Conn, error) {
	var auth *xproxy.Auth
	if p.Username != "" {
		auth = &xproxy.Auth{User: p.Username, Password: p.Password}
	}
	dialer, err := xproxy.SOCKS5("tcp", p.Address, auth, &net.Dialer{Timeout: timeout})
	if err != nil {
		return nil, err
	}
	if cd, ok := dialer.(xproxy.ContextDialer); ok {
		return cd.DialContext(ctx, "tcp", dest)
	}
	return dialWithContext(ctx, func() (net.Conn, error) {
		return dialer.Dial("tcp", dest)
	})
}

// dialHTTPProxy performs an HTTP CONNECT handshake and returns the raw tunnel
// as a net.Conn. Any bytes the CONNECT response reader buffered past the
// headers are preserved for the caller.
func dialHTTPProxy(ctx context.Context, p config.ProxyConfig, dest string, timeout time.Duration) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", p.Address)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	var req strings.Builder
	req.WriteString("CONNECT " + dest + " HTTP/1.1\r\n")
	req.WriteString("Host: " + dest + "\r\n")
	if p.Username != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(p.Username + ":" + p.Password))
		req.WriteString("Proxy-Authorization: Basic " + cred + "\r\n")
	}
	req.WriteString("\r\n")
	if _, err := io.WriteString(conn, req.String()); err != nil {
		_ = conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		_ = resp.Body.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("CONNECT %s: %s %s", dest, resp.Status, strings.TrimSpace(string(body)))
	}
	_ = conn.SetDeadline(time.Time{})
	return &bufferedConn{Conn: conn, r: br}, nil
}

// bufferedConn keeps the bufio.Reader used for the proxy handshake so no
// target bytes read ahead during CONNECT parsing are lost.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// dialWithContext runs a blocking dial in a goroutine so a canceled request
// can stop waiting before the dialer's timeout.
func dialWithContext(ctx context.Context, dial func() (net.Conn, error)) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := dial()
		ch <- result{conn, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.conn, r.err
	}
}
