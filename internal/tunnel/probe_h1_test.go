package tunnel

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"relay-htcp/internal/protocol"
)

// TestProbeH1Streaming verifies the HTTP/1.1 fallback path the server uses for
// tunnel streams (see enableFullDuplex in server.go). A streaming POST (pipe
// body, immediate 200, then PING -> PONG) only works on HTTP/1.1 once the
// handler enables full duplex: without it, the server's Flush would drain the
// request body before the 200 is sent, and the client (which only writes the
// body after receiving the 200) deadlocks. The 10s context bounds the test so
// a regression surfaces as a failure instead of hanging the suite.
func TestProbeH1Streaming(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/tunnel", func(w http.ResponseWriter, r *http.Request) {
		// Mirror the server's enableFullDuplex for the HTTP/1.1 case.
		if err := http.NewResponseController(w).EnableFullDuplex(); err != nil {
			t.Logf("handler: EnableFullDuplex: %v", err)
			http.Error(w, "full duplex unsupported", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		f, err := protocol.NewReader(r.Body).Read()
		if err != nil {
			t.Logf("handler: read: %v", err)
			return
		}
		if f.Type == protocol.TypePing {
			if err := (&protocol.Frame{Type: protocol.TypePong}).Encode(w); err != nil {
				t.Logf("handler: pong encode: %v", err)
				return
			}
			w.(http.Flusher).Flush()
		}
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	protos := &http.Protocols{}
	protos.SetHTTP1(true)
	srv := &http.Server{Handler: mux, Protocols: protos}
	go srv.Serve(ln)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := &http.Client{Transport: &http.Transport{}}
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+ln.Addr().String()+"/tunnel", pr)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client: Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.Proto != "HTTP/1.1" {
		t.Fatalf("proto = %s, want HTTP/1.1", resp.Proto)
	}
	if err := (&protocol.Frame{Type: protocol.TypePing}).Encode(pw); err != nil {
		t.Fatalf("client: ping: %v", err)
	}
	f, err := protocol.NewReader(resp.Body).Read()
	if err != nil {
		t.Fatalf("client: read PONG: %v", err)
	}
	if f.Type != protocol.TypePong {
		t.Fatalf("got %s, want PONG", f)
	}
	_ = pw.Close()
	t.Logf("client: h1 full-duplex streaming OK, got %s", f)
}
