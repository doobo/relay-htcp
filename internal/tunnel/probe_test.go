package tunnel

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"testing"
	"time"

	"relay-htcp/internal/config"
	"relay-htcp/internal/protocol"
)

func clientProbeConfig(serverAddr string) *config.ClientConfig {
	cfg := &config.ClientConfig{
		Server:    serverAddr,
		Auth:      config.ClientAuth{Token: testToken},
		Listeners: []config.Listener{{Local: "127.0.0.1:0", Target: "echo"}},
	}
	cfg.TLS.InsecureSkipVerify = true
	if err := cfg.Validate(); err != nil {
		panic(err)
	}
	return cfg
}

// TestProbeTLS isolates which TLS path fails: plain GET vs streaming POST.
func TestProbeTLS(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()
	serverAddr, stopServer := startTunnelServer(t, target, true)
	defer stopServer()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stock := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	doGet := func(name string, client *http.Client) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, serverAddr+HealthPath, nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Logf("%s GET: FAIL: %v", name, err)
			return
		}
		t.Logf("%s GET: OK status=%s proto=%s", name, resp.Status, resp.Proto)
		resp.Body.Close()
	}
	doGet("stock", stock)

	scfg := clientProbeConfig(serverAddr)
	client, err := newSlotClient(serverAddr, scfg.TLS)
	if err != nil {
		t.Fatalf("newSlotClient: %v", err)
	}
	doGet("slot", client)

	// Streaming control stream: POST with a pipe body, then PING -> PONG.
	pr, pw := io.Pipe()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, serverAddr+ControlPath, pr)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("slot stream: FAIL: %v", err)
	}
	defer resp.Body.Close()
	t.Logf("slot stream: OPENED status=%s proto=%s", resp.Status, resp.Proto)
	if err := (&protocol.Frame{Type: protocol.TypePing}).Encode(pw); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	f, err := protocol.NewReader(resp.Body).Read()
	if err != nil {
		t.Fatalf("slot stream: read FAIL: %v", err)
	}
	t.Logf("slot stream: got %s", f)
	_ = pw.Close()
}
