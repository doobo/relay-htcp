package config

import (
	"strings"
	"testing"
)

func multiServerClient() *ClientConfig {
	return &ClientConfig{
		Auth: ClientAuth{Token: "global-token"},
		Servers: []ServerEndpoint{
			{Name: "primary", URL: "https://a.example.com:443"},
			{Name: "backup", URL: "https://b.example.com:443", Token: "backup-token"},
		},
		Listeners: []Listener{
			{Local: "127.0.0.1:2222", Target: "ssh", Servers: []string{"primary", "backup"}, Strategy: StrategyFailover},
			{Local: "127.0.0.1:33060", Target: "mysql"},
		},
	}
}

func TestClientMultipleServers(t *testing.T) {
	cfg := multiServerClient()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Servers) != 2 {
		t.Fatalf("servers = %d, want 2", len(cfg.Servers))
	}
	if cfg.Listeners[0].Strategy != StrategyFailover {
		t.Fatalf("strategy = %q", cfg.Listeners[0].Strategy)
	}
	if cfg.Listeners[1].Strategy != StrategyRoundRobin {
		t.Fatalf("default strategy = %q, want %q", cfg.Listeners[1].Strategy, StrategyRoundRobin)
	}

	resolved := cfg.ResolvedServers()
	if len(resolved) != 2 {
		t.Fatalf("resolved = %d, want 2", len(resolved))
	}
	if resolved[0].Token != "global-token" || resolved[1].Token != "backup-token" {
		t.Fatalf("tokens = %q / %q", resolved[0].Token, resolved[1].Token)
	}
}

func TestClientServerTLSOverrides(t *testing.T) {
	cfg := &ClientConfig{
		TLS:  ClientTLS{CAFile: "global.crt", InsecureSkipVerify: true},
		Auth: ClientAuth{Token: "token"},
		Servers: []ServerEndpoint{
			{Name: "a", URL: "https://a:443", CAFile: "a.crt"},
			{Name: "b", URL: "https://b:443"},
		},
		Listeners: []Listener{{Local: "127.0.0.1:2222", Target: "ssh"}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	resolved := cfg.ResolvedServers()
	if resolved[0].TLS.CAFile != "a.crt" || !resolved[0].TLS.InsecureSkipVerify {
		t.Fatalf("server a TLS = %+v", resolved[0].TLS)
	}
	if resolved[1].TLS.CAFile != "global.crt" || !resolved[1].TLS.InsecureSkipVerify {
		t.Fatalf("server b TLS = %+v", resolved[1].TLS)
	}
}

func TestClientMigratesLegacyServerField(t *testing.T) {
	cfg := &ClientConfig{
		Server:    "http://127.0.0.1:5630",
		Auth:      ClientAuth{Token: "token"},
		Listeners: []Listener{{Local: "127.0.0.1:2222", Target: "ssh"}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Server != "" {
		t.Fatalf("legacy server not cleared: %q", cfg.Server)
	}
	if len(cfg.Servers) != 1 || cfg.Servers[0].URL != "http://127.0.0.1:5630" {
		t.Fatalf("servers = %+v", cfg.Servers)
	}
}

func TestClientRejectsUnknownListenerServer(t *testing.T) {
	cfg := multiServerClient()
	cfg.Listeners[0].Servers = []string{"primary", "missing"}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "unknown server") {
		t.Fatalf("err = %v", err)
	}
}

func TestClientRejectsDuplicateServerName(t *testing.T) {
	cfg := multiServerClient()
	cfg.Servers[1].Name = "primary"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "duplicate name") {
		t.Fatalf("err = %v", err)
	}
}

func TestClientRejectsInvalidStrategy(t *testing.T) {
	cfg := multiServerClient()
	cfg.Listeners[0].Strategy = "random"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "strategy") {
		t.Fatalf("err = %v", err)
	}
}

func TestClientTransportDefaultsAndValidation(t *testing.T) {
	cfg := multiServerClient()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Servers[0].Transport != TransportHTTP {
		t.Fatalf("default transport = %q, want http", cfg.Servers[0].Transport)
	}
	if cfg.Servers[0].XHTTPPath != DefaultXHTTPPath {
		t.Fatalf("default xhttp path = %q", cfg.Servers[0].XHTTPPath)
	}
	cfg.Servers[0].Transport = TransportXHTTP
	cfg.Servers[0].XHTTPPath = "custom/"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := cfg.ResolvedServers()[0]; got.Transport != TransportXHTTP || got.XHTTPPath != "/custom" {
		t.Fatalf("resolved transport/path = %+v", got)
	}

	cfg.Servers[0].Transport = "carrier-pigeon"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "transport") {
		t.Fatalf("err = %v", err)
	}
	cfg.Servers[0].Transport = TransportXHTTP
	cfg.Servers[0].XHTTPPath = "/xhttp?bad=1"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "xhttp_path") {
		t.Fatalf("err = %v", err)
	}
}

func TestClientProxyDefaultsAndValidation(t *testing.T) {
	cfg := multiServerClient()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Proxy.Enabled {
		t.Fatal("proxy enabled by default")
	}

	cfg.Proxy.Enabled = true
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "address") {
		t.Fatalf("enabled proxy without address: %v", err)
	}

	cfg.Proxy = ClientProxy{
		Enabled: true,
		Address: "http://user:pass@127.0.0.1:7890",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Proxy.Type != ProxyHTTP || cfg.Proxy.Address != "127.0.0.1:7890" ||
		cfg.Proxy.Username != "user" || cfg.Proxy.Password != "pass" {
		t.Fatalf("normalized proxy = %+v", cfg.Proxy)
	}

	cfg.Proxy = ClientProxy{Enabled: true, Type: "socks5h", Address: "127.0.0.1:1080"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Proxy.Type != ProxySOCKS5 {
		t.Fatalf("socks type = %q", cfg.Proxy.Type)
	}

	cfg.Proxy.Type = "ftp"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "type") {
		t.Fatalf("invalid proxy type accepted: %v", err)
	}
}

func TestClientRequiresTokenPerServerOrGlobal(t *testing.T) {
	cfg := multiServerClient()
	cfg.Auth.Token = ""
	cfg.Servers[0].Token = ""
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "token required") {
		t.Fatalf("err = %v", err)
	}
	cfg.Servers[0].Token = "own-token"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("per-server tokens rejected: %v", err)
	}
}

// The shipped example must stay loadable and valid.
func TestClientExampleConfig(t *testing.T) {
	cfg, err := LoadClient("../../config/client.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Servers) < 1 || len(cfg.Listeners) < 1 {
		t.Fatalf("example = %+v", cfg)
	}
}

// BootstrapClient starts with no servers/listeners so the operator can fill
// them in from the admin panel.
func TestBootstrapClient(t *testing.T) {
	cfg, err := BootstrapClient()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Admin.Enabled || cfg.Admin.Listen != "127.0.0.1:15630" {
		t.Fatalf("admin = %+v", cfg.Admin)
	}
	if len(cfg.Servers) != 0 || len(cfg.Listeners) != 0 {
		t.Fatalf("bootstrap servers/listeners = %d/%d, want 0/0", len(cfg.Servers), len(cfg.Listeners))
	}

	// Without the admin panel an empty client is still invalid.
	if err := (&ClientConfig{}).Validate(); err == nil {
		t.Fatal("empty client without admin accepted")
	}
	// But an explicitly enabled admin panel allows the idle bootstrap state.
	idle := &ClientConfig{}
	idle.Admin.Enabled = true
	if err := idle.Validate(); err != nil {
		t.Fatalf("idle client with admin rejected: %v", err)
	}
}
