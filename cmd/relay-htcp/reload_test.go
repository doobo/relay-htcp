package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"relay-htcp/internal/config"
	"relay-htcp/internal/tunnel"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

const reloadBaseYAML = `listen: ":5630"
auth:
  tokens:
    - name: reload
      token: reload-token
routes:
  - name: first
    target: 127.0.0.1:1
`

// TestReloadServerConfigAppliesFile is the SIGHUP contract: hot fields in the
// file take effect immediately and restart-only fields are reported.
func TestReloadServerConfigAppliesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	writeFile(t, path, reloadBaseYAML)

	cfg, err := config.LoadServer(path)
	if err != nil {
		t.Fatal(err)
	}
	srv := tunnel.NewServer(cfg, discardLogger())

	writeFile(t, path, `listen: ":9999"
auth:
  tokens:
    - name: reload
      token: reload-token
      routes: [second]
routes:
  - name: first
    target: 127.0.0.1:1
  - name: second
    target: 127.0.0.1:2
tunnel:
  max_connections: 7
`)
	report, err := reloadServerConfig(srv, nil, path, discardLogger())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	live := srv.CurrentConfigYAML()
	if !strings.Contains(live, "name: second") {
		t.Fatalf("new route missing from live config:\n%s", live)
	}
	if !strings.Contains(live, "max_connections: 7") {
		t.Fatalf("max_connections not applied:\n%s", live)
	}
	if !hasField(report.Applied, "routes") || !hasField(report.Applied, "tunnel.timeouts") {
		t.Fatalf("applied = %v", report.Applied)
	}
	if !hasField(report.RestartRequired, "listen") {
		t.Fatalf("restart_required = %v, want listen", report.RestartRequired)
	}
}

// TestReloadServerConfigKeepsRunningConfigOnBadFile makes sure a typo in the
// file (or a failed validation) never drops the live config.
func TestReloadServerConfigKeepsRunningConfigOnBadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	writeFile(t, path, reloadBaseYAML)

	cfg, err := config.LoadServer(path)
	if err != nil {
		t.Fatal(err)
	}
	srv := tunnel.NewServer(cfg, discardLogger())
	before := srv.CurrentConfigYAML()

	writeFile(t, path, "auth: [this is not valid\n")
	if _, err := reloadServerConfig(srv, nil, path, discardLogger()); err == nil {
		t.Fatal("reload of an invalid file must fail")
	}
	if after := srv.CurrentConfigYAML(); after != before {
		t.Fatalf("running config changed after a failed reload:\nbefore:\n%s\nafter:\n%s", before, after)
	}

	// A valid file with a broken reference is rejected too.
	writeFile(t, path, `auth:
  tokens:
    - name: reload
      token: reload-token
      routes: [missing]
routes:
  - name: first
    target: 127.0.0.1:1
`)
	if _, err := reloadServerConfig(srv, nil, path, discardLogger()); err == nil {
		t.Fatal("reload with an unknown route reference must fail")
	}
	if after := srv.CurrentConfigYAML(); after != before {
		t.Fatal("running config changed after a rejected reload")
	}
}

// TestWatchReload runs the signal fan-out core: one reload per signal, and the
// watcher stops with the context.
func TestWatchReload(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signals := make(chan os.Signal, 2)
	var reloads atomic.Int32
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		watchReload(ctx, signals, discardLogger(), func() { reloads.Add(1) })
	}()

	signals <- os.Interrupt
	signals <- os.Interrupt
	deadline := time.Now().Add(2 * time.Second)
	for reloads.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("reloads = %d, want 2", reloads.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not stop with the context")
	}
}

// TestWatchReloadSignalDoesNotBlock guards the wiring: runServer calls this
// before Serve, so a blocking implementation would keep the listener closed.
func TestWatchReloadSignalDoesNotBlock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		watchReloadSignal(ctx, discardLogger(), func() {})
	}()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("watchReloadSignal blocked its caller instead of watching in the background")
	}
}

func hasField(fields []string, want string) bool {
	for _, f := range fields {
		if f == want {
			return true
		}
	}
	return false
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
