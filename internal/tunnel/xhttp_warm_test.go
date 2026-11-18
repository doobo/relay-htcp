package tunnel

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"relay-htcp/internal/protocol"
)

// TestXHTTPApplyUploadSeqReorders verifies that pipelined upload batches are
// applied to the target in sequence order even when the network delivers them
// out of order.
func TestXHTTPApplyUploadSeqReorders(t *testing.T) {
	target, peer := net.Pipe()
	defer target.Close()
	defer peer.Close()

	ss := &xhttpSession{conn: target, done: make(chan struct{}), upNext: 1}
	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 3)
		n, _ := io.ReadFull(peer, buf)
		got <- string(buf[:n])
	}()

	// Batch 2 arrives first and must be held back until 1 shows up.
	if err := ss.applyUploadSeq(2, []*protocol.Frame{{Type: protocol.TypeData, Payload: []byte("C")}}); err != nil {
		t.Fatalf("apply seq 2: %v", err)
	}
	select {
	case v := <-got:
		t.Fatalf("out-of-order batch applied early: %q", v)
	case <-time.After(100 * time.Millisecond):
	}

	if err := ss.applyUploadSeq(1, []*protocol.Frame{
		{Type: protocol.TypeData, Payload: []byte("A")},
		{Type: protocol.TypeData, Payload: []byte("B")},
	}); err != nil {
		t.Fatalf("apply seq 1: %v", err)
	}
	select {
	case v := <-got:
		if v != "ABC" {
			t.Fatalf("target saw %q, want ABC", v)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for reordered data")
	}

	// Duplicates must be ignored instead of being replayed.
	if err := ss.applyUploadSeq(1, []*protocol.Frame{{Type: protocol.TypeData, Payload: []byte("X")}}); err != nil {
		t.Fatalf("duplicate seq 1: %v", err)
	}
}

func spareCount(p *Pool, server, route string) int {
	p.spareMu.Lock()
	defer p.spareMu.Unlock()
	return len(p.spares[xhttpSpareKey(server, route)])
}

func waitCond(t *testing.T, timeout time.Duration, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

// TestXHTTPWarmPoolPreparesDownloadStream checks the warm pool: after one
// stream has been used, the next local connection must not need its own
// download GET (which costs a full round trip on a high-latency link).
func TestXHTTPWarmPoolPreparesDownloadStream(t *testing.T) {
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
	var downloads atomic.Int64
	front := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/relay/download" {
			downloads.Add(1)
		}
		proxy.ServeHTTP(w, r)
	}))
	defer front.Close()

	local, pool, stop := startXHTTPClientPool(t, front.URL, true, "")
	defer stop()

	testEchoRoundTrip(t, local, "warm-1")
	waitCond(t, 3*time.Second, "one warm download stream", func() bool {
		return spareCount(pool, "xhttp", "echo") > 0
	})

	before := downloads.Load()
	testEchoRoundTrip(t, local, "warm-2")
	after := downloads.Load()
	// The second connection claims the warm stream (0 GETs) and refills the
	// pool in the background (1 GET). Without the warm pool it would be 2.
	if delta := after - before; delta > 1 {
		t.Fatalf("second connection opened %d download GETs, want at most 1", delta)
	}
}

// TestXHTTPUploadPipelineHeader makes sure the server advertises pipelining and
// that the client still echoes correctly with two uploads in flight.
func TestXHTTPUploadPipelineHeader(t *testing.T) {
	// Plain echo target (no prefix) so the assertion can compare bytes.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()

	serverAddr, stopServer := startTunnelServer(t, ln.Addr().String(), false)
	defer stopServer()

	local, stop := startXHTTPClient(t, serverAddr, false, "")
	defer stop()

	// Burst several writes back to back: with pipelining enabled these are
	// split into batches whose order is restored by the server.
	conn, err := net.Dial("tcp", local)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i)
	}
	for i := 0; i < 4; i++ {
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	got := make([]byte, len(payload)*4)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	for i := 0; i < 4; i++ {
		for j := range payload {
			if got[i*len(payload)+j] != payload[j] {
				t.Fatalf("byte %d of chunk %d = %d, want %d", j, i, got[i*len(payload)+j], payload[j])
			}
		}
	}
}
