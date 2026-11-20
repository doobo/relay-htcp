package config

import (
	"testing"
	"time"
)

func TestServerRouteProxySelection(t *testing.T) {
	cfg := &ServerConfig{
		Listen: "127.0.0.1:0",
		Auth:   AuthConfig{Tokens: []Token{{Name: "t", Token: "token"}}},
		Routes: []Route{
			{Name: "direct", Target: "127.0.0.1:22"},
			{Name: "proxied", Target: "127.0.0.1:3306", UseProxy: true},
		},
		Proxy: ProxyConfig{Enabled: true, Type: "http", Address: "127.0.0.1:7890"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.RouteUsesProxy("direct") {
		t.Fatal("direct route reported proxy use")
	}
	if !cfg.RouteUsesProxy("proxied") {
		t.Fatal("proxied route did not report proxy use")
	}
	if target, ok := cfg.RouteTarget("proxied"); !ok || target != "127.0.0.1:3306" {
		t.Fatalf("route target = %q %v", target, ok)
	}
}

func TestTargetAddress(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		bad      bool
	}{
		{in: "127.0.0.1:22", want: "127.0.0.1:22"},
		{in: "[::1]:3306", want: "[::1]:3306"},
		{in: "https://ws.didton.com", want: "ws.didton.com:443"},
		{in: "http://gcore.didton.com", want: "gcore.didton.com:80"},
		{in: "https://ws.didton.com:8443/", want: "ws.didton.com:8443"},
		{in: "http://[2001:db8::1]", want: "[2001:db8::1]:80"},
		{in: "https://user:pass@ws.didton.com", bad: true},
		{in: "https://ws.didton.com/path", bad: true},
		{in: "ftp://ws.didton.com", bad: true},
		{in: "ws.didton.com", bad: true},
		{in: "https:///nohost", bad: true},
		{in: "", bad: true},
	} {
		got, err := TargetAddress(tc.in)
		if tc.bad {
			if err == nil {
				t.Errorf("TargetAddress(%q) = %q, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("TargetAddress(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("TargetAddress(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestServerRouteTargetURL(t *testing.T) {
	cfg := &ServerConfig{
		Listen: "127.0.0.1:0",
		Auth:   AuthConfig{Tokens: []Token{{Name: "t", Token: "token"}}},
		Routes: []Route{
			{Name: "ws", Target: "https://ws.didton.com"},
			{Name: "gcore", Target: "http://gcore.didton.com"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if got, _ := cfg.RouteTarget("ws"); got != "ws.didton.com:443" {
		t.Fatalf("ws target = %q", got)
	}
	if got, _ := cfg.RouteTarget("gcore"); got != "gcore.didton.com:80" {
		t.Fatalf("gcore target = %q", got)
	}
}

func TestServerProxyValidation(t *testing.T) {
	base := func() *ServerConfig {
		return &ServerConfig{
			Listen: "127.0.0.1:0",
			Auth:   AuthConfig{Tokens: []Token{{Name: "t", Token: "token"}}},
			Routes: []Route{{Name: "r", Target: "127.0.0.1:22"}},
		}
	}

	cfg := base()
	cfg.Proxy = ProxyConfig{Enabled: true, Type: "socks5", Address: "127.0.0.1:1080"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid socks5 proxy: %v", err)
	}
	if cfg.Proxy.Type != ProxySOCKS5 {
		t.Fatalf("proxy type = %q", cfg.Proxy.Type)
	}

	cfg = base()
	cfg.Proxy = ProxyConfig{Enabled: true, Address: "not-an-address"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid proxy address accepted")
	}

	// Disabled proxy may stay empty.
	cfg = base()
	cfg.Proxy = ProxyConfig{}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled proxy: %v", err)
	}
}

func TestServerRouteTypes(t *testing.T) {
	base := func() *ServerConfig {
		return &ServerConfig{
			Listen: "127.0.0.1:0",
			Auth:   AuthConfig{Tokens: []Token{{Name: "t", Token: "token"}}},
			Routes: []Route{
				{Name: "tcp", Target: "127.0.0.1:22"},
				{Name: "pair", Type: "stcp"},
			},
		}
	}

	cfg := base()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Routes[0].Type != RouteTypeTCP {
		t.Fatalf("default type = %q, want %q", cfg.Routes[0].Type, RouteTypeTCP)
	}
	if !cfg.RouteIsSTCP("pair") {
		t.Fatal("pair route is not stcp")
	}
	if kind, ok := cfg.RouteKind("tcp"); !ok || kind != RouteTypeTCP {
		t.Fatalf("RouteKind(tcp) = %q %v", kind, ok)
	}
	if target, ok := cfg.RouteTarget("pair"); ok || target != "" {
		t.Fatalf("stcp route reported target %q", target)
	}
	if cfg.Tunnel.STCPTimeout != 30*time.Second {
		t.Fatalf("stcp default timeout = %v", cfg.Tunnel.STCPTimeout)
	}

	cfg = base()
	cfg.Routes[0].Target = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("tcp route without target accepted")
	}

	cfg = base()
	cfg.Routes[1].Target = "127.0.0.1:80"
	if err := cfg.Validate(); err == nil {
		t.Fatal("stcp route with target accepted")
	}

	cfg = base()
	cfg.Routes[1].Type = "udp"
	if err := cfg.Validate(); err == nil {
		t.Fatal("unknown route type accepted")
	}

	cfg = base()
	cfg.Auth.Tokens[0].Routes = []string{"pair"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("token referencing an stcp route rejected: %v", err)
	}
}
