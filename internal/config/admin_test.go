package config

import (
	"path/filepath"
	"testing"
)

func minimalServerConfig() *ServerConfig {
	return &ServerConfig{
		Listen: "127.0.0.1:0",
		Auth:   AuthConfig{Tokens: []Token{{Name: "t", Token: "token"}}},
		Routes: []Route{{Name: "ssh", Target: "127.0.0.1:22"}},
	}
}

func TestAdminSharedDefaults(t *testing.T) {
	cfg := minimalServerConfig()
	cfg.Admin.Enabled = true
	cfg.Admin.Shared = true
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Admin.Path != "/admin" {
		t.Fatalf("path = %q, want /admin", cfg.Admin.Path)
	}
	if len(cfg.Admin.AllowedCIDRs) != 2 ||
		cfg.Admin.AllowedCIDRs[0] != "0.0.0.0/0" || cfg.Admin.AllowedCIDRs[1] != "::/0" {
		t.Fatalf("shared mode allowed_cidrs = %v, want allow-all", cfg.Admin.AllowedCIDRs)
	}
}

func TestAdminStandaloneDefaultsToRoot(t *testing.T) {
	cfg := minimalServerConfig()
	cfg.Admin.Enabled = true
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Admin.Path != "/" {
		t.Fatalf("standalone path = %q, want /", cfg.Admin.Path)
	}
}

func TestAdminPathNormalization(t *testing.T) {
	cfg := minimalServerConfig()
	cfg.Admin.Enabled = true
	cfg.Admin.Shared = true
	cfg.Admin.Path = "ops-console/"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Admin.Path != "/ops-console" {
		t.Fatalf("path = %q", cfg.Admin.Path)
	}
}

func TestAdminSharedRejectsRootAndTunnelPaths(t *testing.T) {
	for _, path := range []string{"/", "/tunnel", "/stream", "/health"} {
		cfg := minimalServerConfig()
		cfg.Admin.Enabled = true
		cfg.Admin.Shared = true
		cfg.Admin.Path = path
		if err := cfg.Validate(); err == nil {
			t.Fatalf("shared path %q accepted", path)
		}
	}
}

func TestClientRejectsSharedAdmin(t *testing.T) {
	cfg := &ClientConfig{
		Server:    "http://127.0.0.1:1",
		Auth:      ClientAuth{Token: "token"},
		Listeners: []Listener{{Local: "127.0.0.1:0", Target: "ssh"}},
	}
	cfg.Admin.Shared = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("client accepted admin.shared")
	}
}

func TestServerListenDefaultsTo5630(t *testing.T) {
	cfg := minimalServerConfig()
	cfg.Listen = ""
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != DefaultListen {
		t.Fatalf("listen = %q, want :5630", cfg.Listen)
	}
}

func TestTokenRoutes(t *testing.T) {
	cfg := minimalServerConfig()
	cfg.Routes = append(cfg.Routes, Route{Name: "mysql", Target: "127.0.0.1:3306"})

	// Multiple routes are allowed.
	cfg.Auth.Tokens[0].Routes = []string{"ssh", "mysql"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("multiple routes rejected: %v", err)
	}

	cfg.Auth.Tokens[0].Routes = []string{"ssh", "unknown"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("token with an unknown route accepted")
	}

	cfg.Auth.Tokens[0].Routes = []string{"ssh"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid single route rejected: %v", err)
	}

	cfg.Auth.Tokens[0].Routes = nil
	if err := cfg.Validate(); err != nil {
		t.Fatalf("empty routes rejected: %v", err)
	}
}

func TestLogLevelDefaultsToInfo(t *testing.T) {
	cfg := minimalServerConfig()
	cfg.Log.Level = ""
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Log.Level != "info" {
		t.Fatalf("log level = %q, want info", cfg.Log.Level)
	}

	cfg.Log.Level = "verbose"
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid log level accepted")
	}
}

func TestBootstrapServer(t *testing.T) {
	cfg, err := BootstrapServer()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != DefaultListen {
		t.Fatalf("listen = %q", cfg.Listen)
	}
	if !cfg.Admin.Enabled || !cfg.Admin.Shared || cfg.Admin.Path != "/admin" {
		t.Fatalf("admin = %+v", cfg.Admin)
	}
	if cfg.Admin.DBPath != filepath.Join("data", "admin.db") {
		t.Fatalf("db path = %q", cfg.Admin.DBPath)
	}
	if cfg.Admin.KeyFile != filepath.Join("data", "admin.db.key") {
		t.Fatalf("key file = %q", cfg.Admin.KeyFile)
	}
	if len(cfg.Admin.AllowedCIDRs) != 2 || cfg.Admin.AllowedCIDRs[0] != "0.0.0.0/0" {
		t.Fatalf("bootstrap allowed_cidrs = %v", cfg.Admin.AllowedCIDRs)
	}
	if len(cfg.Auth.Tokens) != 1 || cfg.Auth.Tokens[0].On() {
		t.Fatalf("bootstrap token should be a disabled placeholder: %+v", cfg.Auth.Tokens)
	}
	if _, ok := cfg.RouteTarget("default"); !ok {
		t.Fatal("bootstrap config has no default route")
	}
}
