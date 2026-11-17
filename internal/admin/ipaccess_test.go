package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestIPAccessRules(t *testing.T) {
	rules, err := parseIPAccess(IPAccessSettings{
		Whitelist: []string{"203.0.113.0/24", "2001:db8::1"},
		Blacklist: []string{"203.0.113.7", "127.0.0.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	cases := map[string]bool{
		"203.0.113.5":  true,  // whitelisted
		"203.0.113.7":  false, // blacklisted wins
		"198.51.100.1": false, // not whitelisted
		"127.0.0.1":    true,  // loopback is never filtered
		"2001:db8::1":  true,
		"2001:db8::2":  false,
	}
	for ip, want := range cases {
		if got := rules.allows(addr(ip)); got != want {
			t.Fatalf("%s allowed = %v, want %v", ip, got, want)
		}
	}
	if _, err := parseIPAccess(IPAccessSettings{Whitelist: []string{"not-an-ip"}}); err == nil {
		t.Fatal("invalid whitelist entry accepted")
	}
}

func TestRequestIPHandlesCloudflared(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("CF-Connecting-IP", "203.0.113.7")
	if got := requestIP(req).String(); got != "203.0.113.7" {
		t.Fatalf("cloudflared IP = %s", got)
	}

	// A public peer cannot spoof forwarding headers.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.5:1234"
	req.Header.Set("CF-Connecting-IP", "203.0.113.7")
	if got := requestIP(req).String(); got != "198.51.100.5" {
		t.Fatalf("untrusted peer IP = %s", got)
	}

	// A loopback proxy may use X-Forwarded-For; the first entry is the client.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
	if got := requestIP(req).String(); got != "203.0.113.7" {
		t.Fatalf("xff IP = %s", got)
	}

	// A private LAN peer is not a trusted proxy: spoofed headers are ignored.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("CF-Connecting-IP", "127.0.0.1")
	if got := requestIP(req).String(); got != "10.0.0.5" {
		t.Fatalf("private peer spoof = %s", got)
	}
}

func TestIPAccessAPI(t *testing.T) {
	env := setupEnv(t)
	_, lr := login(t, env.srv, "admin", "adminpass1")
	token := lr.Token

	do := func(method, path, remote string, body any) (int, []byte) {
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req := httptest.NewRequest(method, path, rd)
		req.RemoteAddr = remote
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		env.srv.Handler().ServeHTTP(w, req)
		return w.Code, w.Body.Bytes()
	}

	// Empty lists: everyone passes.
	if code, raw := do(http.MethodGet, "/api/ip-access", "192.0.2.10:1234", nil); code != http.StatusOK {
		t.Fatalf("empty rules get: %d %s", code, raw)
	}

	// Whitelist only: public addresses are rejected, loopback always passes.
	code, raw := do(http.MethodPut, "/api/ip-access", "127.0.0.1:1234", IPAccessSettings{
		Whitelist: []string{"203.0.113.0/24"},
	})
	if code != http.StatusOK {
		t.Fatalf("put whitelist: %d %s", code, raw)
	}
	if code, _ := do(http.MethodGet, "/api/ip-access", "192.0.2.10:1234", nil); code != http.StatusForbidden {
		t.Fatalf("public after whitelist = %d, want 403", code)
	}
	if code, _ := do(http.MethodGet, "/api/ip-access", "127.0.0.1:1234", nil); code != http.StatusOK {
		t.Fatalf("loopback after whitelist = %d, want 200", code)
	}

	// Cloudflared: the forwarded client IP is used when the peer is local.
	req := httptest.NewRequest(http.MethodGet, "/api/ip-access", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("CF-Connecting-IP", "203.0.113.5")
	w := httptest.NewRecorder()
	env.srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("cloudflared client in whitelist = %d, want 200", w.Code)
	}

	// Blacklist filters an otherwise allowed address.
	code, raw = do(http.MethodPut, "/api/ip-access", "127.0.0.1:1234", IPAccessSettings{
		Blacklist: []string{"203.0.113.5"},
	})
	if code != http.StatusOK {
		t.Fatalf("put blacklist: %d %s", code, raw)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/ip-access", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("CF-Connecting-IP", "203.0.113.5")
	w = httptest.NewRecorder()
	env.srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("blacklisted cloudflared client = %d, want 403", w.Code)
	}

	// Rules are persisted.
	saved, err := env.store.LoadIPAccess()
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Blacklist) != 1 || saved.Blacklist[0] != "203.0.113.5" {
		t.Fatalf("saved = %+v", saved)
	}

	// Clearing the lists opens access again.
	code, _ = do(http.MethodPut, "/api/ip-access", "127.0.0.1:1234", IPAccessSettings{})
	if code != http.StatusOK {
		t.Fatal("clear rules failed")
	}
	if code, _ := do(http.MethodGet, "/api/ip-access", "192.0.2.10:1234", nil); code != http.StatusOK {
		t.Fatalf("public after clear = %d, want 200", code)
	}
}
