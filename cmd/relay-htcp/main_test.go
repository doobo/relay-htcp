package main

import (
	"os"
	"path/filepath"
	"testing"

	"relay-htcp/internal/config"
)

func TestListenOverride(t *testing.T) {
	cases := []struct {
		listen string
		port   int
		want   string
	}{
		{"", 0, ""},
		{"5630", 0, ":5630"},
		{":5630", 0, ":5630"},
		{"127.0.0.1:5630", 0, "127.0.0.1:5630"},
		{"", 5630, ":5630"},
		{"127.0.0.1:1", 5630, ":5630"},
	}
	for _, tc := range cases {
		if got := listenOverride(tc.listen, tc.port); got != tc.want {
			t.Fatalf("listenOverride(%q, %d) = %q, want %q", tc.listen, tc.port, got, tc.want)
		}
	}
}

func TestLoadServerConfigWithoutFile(t *testing.T) {
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(old) }()

	cfg, used, err := loadServerConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if used != "" {
		t.Fatalf("bootstrap used config path %q", used)
	}
	if !cfg.Admin.Enabled || !cfg.Admin.Shared || cfg.Admin.Path != "/admin" {
		t.Fatalf("bootstrap admin = %+v", cfg.Admin)
	}
	if cfg.Listen != config.DefaultListen {
		t.Fatalf("listen = %q", cfg.Listen)
	}
}

func TestResolveClientConfigBootstrap(t *testing.T) {
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(old) }()

	want := filepath.Join("data", "client.yaml")
	path, created, err := resolveClientConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if path != want || !created {
		t.Fatalf("resolve = %q created=%v, want %q created=true", path, created, want)
	}
	if _, err := config.LoadClient(path); err != nil {
		t.Fatalf("bootstrap config is not loadable: %v", err)
	}

	// The second run reuses the file instead of recreating it.
	path2, created2, err := resolveClientConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if path2 != want || created2 {
		t.Fatalf("second resolve = %q created=%v", path2, created2)
	}
}

func TestResolveClientConfigLegacyAndExplicit(t *testing.T) {
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(old) }()

	if err := os.WriteFile("client.yaml", []byte("server: http://127.0.0.1:1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path, created, err := resolveClientConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if path != "client.yaml" || created {
		t.Fatalf("legacy resolve = %q created=%v", path, created)
	}

	// data/client.yaml wins over ./client.yaml when both exist.
	if err := os.MkdirAll("data", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("data", "client.yaml"), []byte("servers: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path, created, err = resolveClientConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join("data", "client.yaml") || created {
		t.Fatalf("data resolve = %q created=%v", path, created)
	}

	if path, _, err := resolveClientConfig("custom.yaml"); err != nil || path != "custom.yaml" {
		t.Fatalf("explicit resolve = %q err=%v", path, err)
	}
}
