package config

import "testing"

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
	if len(cfg.Admin.AllowedCIDRs) == 0 {
		t.Fatal("shared mode did not default to a loopback allowlist")
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
