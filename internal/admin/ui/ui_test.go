package ui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerServesAssets(t *testing.T) {
	h := Handler()
	for path, want := range map[string]string{
		"/":                    "Relay-Htcp",
		"/app.js":              "encryptWithWebCrypto",
		"/style.css":           "--bg",
		"/theme.js":            "data-theme",
		"/favicon.svg":         "<svg",
		"/vendor/tweetnacl.js": "nacl",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s: status %d, want 200", path, w.Code)
		}
		body, _ := io.ReadAll(w.Result().Body)
		if !strings.Contains(string(body), want) {
			t.Fatalf("GET %s: body missing %q", path, want)
		}
	}
	if !strings.Contains(string(mustRead(t, h, "/")), "data-theme-select") {
		t.Fatal("index.html is missing the theme picker")
	}
	if !strings.Contains(string(mustRead(t, h, "/")), "restart-btn") {
		t.Fatal("index.html is missing the restart button")
	}
	if !strings.Contains(string(mustRead(t, h, "/app.js")), "multiSelectHTML") {
		t.Fatal("app.js is missing the dropdown multi-select widget")
	}
	if !strings.Contains(string(mustRead(t, h, "/app.js")), "passwordDialog") {
		t.Fatal("app.js is missing the two-field password dialog")
	}
	if !strings.Contains(string(mustRead(t, h, "/app.js")), "loadTraffic") {
		t.Fatal("app.js is missing the daily traffic panel")
	}
	if !strings.Contains(string(mustRead(t, h, "/style.css")), ".ms-menu") {
		t.Fatal("style.css is missing the dropdown multi-select styles")
	}
	if !strings.Contains(string(mustRead(t, h, "/style.css")), ".traffic-bar") {
		t.Fatal("style.css is missing the traffic panel styles")
	}
	if !strings.Contains(string(mustRead(t, h, "/")), "password-dialog") {
		t.Fatal("index.html is missing the password dialog")
	}
	if !strings.Contains(string(mustRead(t, h, "/")), "traffic-section") {
		t.Fatal("index.html is missing the traffic section")
	}
	req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("app.js Cache-Control = %q, want no-store", cc)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("Content-Security-Policy = %q, want frame-ancestors 'none'", csp)
	}
}

func mustRead(t *testing.T, h http.Handler, path string) []byte {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body, _ := io.ReadAll(w.Result().Body)
	return body
}
