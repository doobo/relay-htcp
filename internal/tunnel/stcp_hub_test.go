package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestSTCPHubPairsByRole(t *testing.T) {
	h := newSTCPHub()
	ctx := context.Background()

	type result struct {
		conn net.Conn
		err  error
	}
	provCh := make(chan result, 1)
	go func() {
		conn, err := h.pair(ctx, "route", TunnelRoleProvider, "p1", time.Second)
		provCh <- result{conn, err}
	}()

	deadline := time.Now().Add(time.Second)
	for h.busyProvider("route") == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if h.busyProvider("route") != 1 {
		t.Fatal("provider stream was not queued")
	}

	visitor, err := h.pair(ctx, "route", TunnelRoleVisitor, "", time.Second)
	if err != nil {
		t.Fatalf("visitor pair: %v", err)
	}
	defer visitor.Close()

	prov := <-provCh
	if prov.err != nil {
		t.Fatalf("provider pair: %v", prov.err)
	}
	defer prov.conn.Close()

	// Data written by the provider must reach the visitor and back.
	go func() {
		buf := make([]byte, 5)
		if _, err := io.ReadFull(visitor, buf); err == nil {
			_, _ = visitor.Write(buf)
		}
	}()
	if _, err := prov.conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(prov.conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("echo = %q", got)
	}
}

func TestSTCPHubTimeout(t *testing.T) {
	h := newSTCPHub()
	start := time.Now()
	_, err := h.pair(context.Background(), "route", TunnelRoleVisitor, "", 40*time.Millisecond)
	if !errors.Is(err, errSTCPNoPeer) {
		t.Fatalf("err = %v, want errSTCPNoPeer", err)
	}
	if elapsed := time.Since(start); elapsed < 30*time.Millisecond {
		t.Fatalf("returned after %v, before the timeout", elapsed)
	}
	if h.busyProvider("route") != 0 {
		t.Fatal("timed-out waiter stayed queued")
	}
}
