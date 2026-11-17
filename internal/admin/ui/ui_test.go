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
}

func mustRead(t *testing.T, h http.Handler, path string) []byte {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body, _ := io.ReadAll(w.Result().Body)
	return body
}
