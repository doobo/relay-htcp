package config

import (
	"strings"
	"testing"
)

func providerProxyConfig(proxy ProxyConfig) *ClientConfig {
	return &ClientConfig{
		Auth:      ClientAuth{Token: "tok"},
		Servers:   []ServerEndpoint{{Name: "s", URL: "http://127.0.0.1:1"}},
		Providers: []Provider{{Route: "h2", Local: "127.0.0.1:8080", UseProxy: true}},
		Proxy:     proxy,
	}
}

func TestServerUseProxyNeedsEnabledProxy(t *testing.T) {
	cfg := &ClientConfig{
		Auth:      ClientAuth{Token: "tok"},
		Servers:   []ServerEndpoint{{Name: "s", URL: "http://127.0.0.1:1", UseProxy: true}},
		Listeners: []Listener{{Local: "127.0.0.1:0", Target: "ssh"}},
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "servers[0].use_proxy: requires proxy.enabled") {
		t.Fatalf("err = %v, want servers[0].use_proxy requires proxy.enabled", err)
	}
	cfg.Proxy = ProxyConfig{Enabled: true, Type: ProxyHTTP, Address: "127.0.0.1:3128"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid server use_proxy rejected: %v", err)
	}
	if got := cfg.ResolvedServers()[0]; !got.UseProxy {
		t.Fatalf("resolved server lost use_proxy: %+v", got)
	}
}

func TestServerWithoutUseProxyStaysDirect(t *testing.T) {
	cfg := &ClientConfig{
		Auth:      ClientAuth{Token: "tok"},
		Servers:   []ServerEndpoint{{Name: "s", URL: "http://127.0.0.1:1"}},
		Listeners: []Listener{{Local: "127.0.0.1:0", Target: "ssh"}},
		Proxy:     ProxyConfig{Enabled: true, Type: ProxyHTTP, Address: "127.0.0.1:3128"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := cfg.ResolvedServers()[0]; got.UseProxy {
		t.Fatalf("server without use_proxy resolved as proxied: %+v", got)
	}
}

func TestLegacySingleServerKeepsProxy(t *testing.T) {
	cfg := &ClientConfig{
		Auth:      ClientAuth{Token: "tok"},
		Server:    "http://127.0.0.1:1",
		Listeners: []Listener{{Local: "127.0.0.1:0", Target: "ssh"}},
		Proxy:     ProxyConfig{Enabled: true, Type: ProxyHTTP, Address: "127.0.0.1:3128"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := cfg.ResolvedServers()[0]; !got.UseProxy {
		t.Fatalf("legacy server lost the global proxy: %+v", got)
	}
}

func TestProviderUseProxyNeedsEnabledProxy(t *testing.T) {
	err := providerProxyConfig(ProxyConfig{}).Validate()
	if err == nil || !strings.Contains(err.Error(), "requires proxy.enabled") {
		t.Fatalf("err = %v, want requires proxy.enabled", err)
	}
	ok := providerProxyConfig(ProxyConfig{Enabled: true, Type: ProxyHTTP, Address: "127.0.0.1:3128"})
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid use_proxy rejected: %v", err)
	}
}
