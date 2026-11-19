package tunnel

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"relay-htcp/internal/protocol"
)

// gatedWriter is a ResponseWriter whose second Write blocks. The first write is
// the handler's padding frame; the second is the first frame from the
// target->download pump, which is where a cancelled stream used to race with
// the handler returning.
type gatedWriter struct {
	hdr     http.Header
	entered chan struct{} // closed when the pump's write starts
	release chan struct{} // closed by the test to let that write finish
	writes  atomic.Int32

	handlerDone atomic.Bool // set once ServeHTTP returned
	lateWrite   atomic.Bool // set if the writer is touched after that
}

func newGatedWriter() *gatedWriter {
	return &gatedWriter{
		hdr:     make(http.Header),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (g *gatedWriter) Header() http.Header { return g.hdr }

func (g *gatedWriter) WriteHeader(int) {}

func (g *gatedWriter) noteUse() {
	if g.handlerDone.Load() {
		g.lateWrite.Store(true)
	}
}

func (g *gatedWriter) Write(p []byte) (int, error) {
	g.noteUse()
	if g.writes.Add(1) == 2 {
		close(g.entered)
		<-g.release
	}
	return len(p), nil
}

func (g *gatedWriter) Flush() { g.noteUse() }

// startChattyTarget accepts one connection and writes a single chunk without
// waiting for a request, so the download pump has data to forward immediately.
func startChattyTarget(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var conns []net.Conn
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		conns = append(conns, c)
		_, _ = c.Write([]byte("hello"))
		buf := make([]byte, 1024)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		for _, c := range conns {
			_ = c.Close()
		}
	}
}

// TestXHTTPDownloadWaitsForPumpOnCancel reproduces the production crash:
// net/http's HTTP/2 ResponseWriter panics with "Header called after Handler
// finished" when a frame is written after the download handler returned. The
// write happens on the target->download goroutine, so the panic is not
// recovered by net/http and takes the whole process down. The handler must
// therefore wait for that goroutine before returning.
func TestXHTTPDownloadWaitsForPumpOnCancel(t *testing.T) {
	target, stopTarget := startChattyTarget(t)
	defer stopTarget()
	srv := NewServer(serverConfigFor(target), testLogger())

	const sessionID = "lifetime-test-session"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := httptest.NewRequest(http.MethodGet, "/relay/download?session="+sessionID+"&target=echo", nil).
		WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+testToken)
	r.Header.Set("X-Tunnel-Target", "echo")

	w := newGatedWriter()
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		srv.ServeHTTP(w, r)
	}()

	select {
	case <-w.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("download pump never wrote a frame")
	}

	// The client (or CDN edge) goes away while the pump holds the response.
	cancel()

	select {
	case <-serveDone:
		t.Fatal("download handler returned while a frame write was still in flight")
	case <-time.After(200 * time.Millisecond):
	}

	close(w.release)

	select {
	case <-serveDone:
	case <-time.After(5 * time.Second):
		t.Fatal("download handler did not finish after the in-flight write completed")
	}

	if w.lateWrite.Load() {
		t.Fatal("response writer was used after the download handler returned")
	}
	if ss := srv.getXHTTPSession(sessionID); ss != nil {
		t.Fatal("xhttp session still registered after the handler returned")
	}
}

// TestXHTTPSessionSendAfterCloseWriter pins the invariant the handler relies
// on: once closeWriter has run, send refuses to touch the response.
func TestXHTTPSessionSendAfterCloseWriter(t *testing.T) {
	w := &flusherWriter{hdr: make(http.Header)}
	ss := &xhttpSession{id: "s", done: make(chan struct{}), w: w, fl: w}
	ss.closeWriter()
	if err := ss.send(&protocol.Frame{Type: protocol.TypeClose}); err == nil {
		t.Fatal("send after closeWriter must fail")
	}
	if w.used {
		t.Fatal("send after closeWriter wrote to the response")
	}
}

type flusherWriter struct {
	hdr  http.Header
	used bool
}

func (w *flusherWriter) Header() http.Header { return w.hdr }
func (w *flusherWriter) WriteHeader(int)     {}
func (w *flusherWriter) Write(p []byte) (int, error) {
	w.used = true
	return len(p), nil
}
func (w *flusherWriter) Flush() { w.used = true }
