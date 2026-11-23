package tunnel

import (
	"testing"

	"relay-htcp/internal/config"
)

// A server connection only goes through the outbound proxy when the server
// opts in with use_proxy; a provider's use_proxy never affects it.
func TestServerProxyIsPerServer(t *testing.T) {
	px := config.ClientProxy{Enabled: true, Type: config.ProxyHTTP, Address: "127.0.0.1:7890"}

	direct := serverProxy(config.ResolvedServer{Name: "a", URL: "http://127.0.0.1:5630"}, px)
	if direct.Enabled {
		t.Fatal("server without use_proxy was routed through the proxy")
	}
	via := serverProxy(config.ResolvedServer{Name: "b", URL: "http://127.0.0.1:5630", UseProxy: true}, px)
	if !via.Enabled || via.Address != px.Address {
		t.Fatalf("server with use_proxy = %+v, want the proxy", via)
	}
}
