package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"relay-htcp/internal/admin"
	"relay-htcp/internal/admin/ui"
)

// TestAdminFullStack wires a real tunnel server with the real admin panel
// (SQLite store, login, embedded UI) and walks the operator flow:
// log in -> read status -> save config -> verify hot-apply -> verify the
// saved config survives a simulated restart.
func TestAdminFullStack(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()

	// Real tunnel server.
	cfg := serverConfigFor(target)
	srv := NewServer(cfg, testLogger())
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.ServeListener(ctx, ln)
	waitForAddr(t, ln.Addr().String())
	serverAddr := "http://" + ln.Addr().String()

	// Fresh admin database + seeded user.
	store, err := admin.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(); err != nil {
		t.Fatal(err)
	}
	hash, err := admin.HashPassword("fullstack-pass-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnsureDefaultUser("admin", hash); err != nil {
		t.Fatal(err)
	}

	// Real admin panel on a real listener.
	asrv := admin.NewServer(store, srv, admin.Options{
		Version:    "e2e",
		SessionTTL: time.Hour,
		Source:     "file",
	}, ui.Handler(), testLogger())
	aln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go asrv.Serve(ctx, aln)
	adminAddr := aln.Addr().String()

	do := func(method, path, token string, body any) (int, map[string]any) {
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, "http://"+adminAddr+path, rd)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		out := map[string]any{}
		if len(data) > 0 {
			_ = json.Unmarshal(data, &out)
		}
		return resp.StatusCode, out
	}

	// 1. Login: wrong password rejected, right password accepted.
	if code, _ := do(http.MethodPost, "/api/auth/login", "",
		map[string]string{"username": "admin", "password": "wrong"}); code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d, want 401", code)
	}
	code, out := do(http.MethodPost, "/api/auth/login", "",
		map[string]string{"username": "admin", "password": "fullstack-pass-1"})
	if code != http.StatusOK {
		t.Fatalf("login: %d %v", code, out)
	}
	token, _ := out["token"].(string)
	if token == "" {
		t.Fatal("login: no token in response")
	}

	// 2. Status reports the live server.
	code, out = do(http.MethodGet, "/api/status", token, nil)
	if code != http.StatusOK {
		t.Fatalf("status: %d", code)
	}
	if out["role"] != "server" || out["version"] != "e2e" {
		t.Fatalf("status = %v", out)
	}

	// 3. The UI is served on /.
	resp, err := http.Get("http://" + adminAddr + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("relay-htcp")) {
		t.Fatalf("ui: %d, body len %d", resp.StatusCode, len(body))
	}

	// 4. A data request for the (not yet existing) route echo2 is rejected.
	dataStatus := func(route string) int {
		req, _ := http.NewRequest(http.MethodPost, serverAddr+DataPath, nil)
		req.Header.Set("Authorization", "Bearer "+testToken)
		req.Header.Set("X-Tunnel-Target", route)
		dresp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = dresp.Body.Close()
		return dresp.StatusCode
	}
	if code := dataStatus("echo2"); code != http.StatusNotFound {
		t.Fatalf("echo2 before save: %d, want 404", code)
	}

	// 5. Save a config that adds route echo2; it must hot-apply.
	newYAML := fmt.Sprintf(`listen: %q
auth:
  tokens:
    - name: e2e
      token: %q
routes:
  - name: echo
    target: %q
  - name: echo2
    target: %q
`, ln.Addr().String(), testToken, target, target)
	code, out = do(http.MethodPut, "/api/config", token, map[string]string{"yaml": newYAML})
	if code != http.StatusOK {
		t.Fatalf("put config: %d %v", code, out)
	}
	if code := dataStatus("echo2"); code != http.StatusOK {
		t.Fatalf("echo2 after save: %d, want 200 (hot-applied)", code)
	}

	// 6. The saved config is persisted in the database.
	saved, err := store.GetSetting(admin.ConfigKey)
	if err != nil {
		t.Fatal(err)
	}
	newCfg, err := parseServerYAML(saved)
	if err != nil {
		t.Fatalf("saved yaml invalid: %v", err)
	}
	if _, ok := newCfg.RouteTarget("echo2"); !ok {
		t.Fatal("saved config missing route echo2")
	}

	// 6b. Structured form: the schema-driven editor never returns secrets and
	// resubmitting a masked secret keeps the stored token.
	code, form := do(http.MethodGet, "/api/config/form", token, nil)
	if code != http.StatusOK {
		t.Fatalf("get config form: %d", code)
	}
	if strings.Contains(fmt.Sprint(form), testToken) {
		t.Fatal("config form leaked a token")
	}
	values, _ := form["values"].(map[string]any)
	if values == nil || values["listen"] == "" {
		t.Fatalf("form values = %v", values)
	}
	tokenRows, _ := values["auth.tokens"].([]any)
	if len(tokenRows) != 1 || tokenRows[0].(map[string]any)["token"] != "" {
		t.Fatalf("form token rows = %v", tokenRows)
	}
	// Change a scalar, then submit the masked rows back unchanged.
	values["disguise.enabled"] = false
	code, out = do(http.MethodPut, "/api/config/form", token, map[string]any{"values": values})
	if code != http.StatusOK {
		t.Fatalf("put config form: %d %v", code, out)
	}
	if srv.cfgGet().Disguise.On() {
		t.Fatal("form save did not hot-apply disguise.enabled")
	}
	if c := dataStatus("echo2"); c != http.StatusOK {
		t.Fatalf("masked token was lost by form save: echo2 = %d", c)
	}
	formSaved, err := store.GetSetting(admin.ConfigKey)
	if err != nil {
		t.Fatal(err)
	}
	newCfg, err = parseServerYAML(formSaved)
	if err != nil {
		t.Fatalf("form-saved yaml invalid: %v", err)
	}

	// 7. Simulated restart: a fresh server built from the saved config
	// serves the new route over a real connection.
	srv2 := NewServer(newCfg, testLogger())
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv2.ServeListener(ctx, ln2)
	waitForAddr(t, ln2.Addr().String())
	req, _ := http.NewRequest(http.MethodPost, "http://"+ln2.Addr().String()+DataPath, nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-Tunnel-Target", "echo2")
	dresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = dresp.Body.Close()
	if dresp.StatusCode != http.StatusOK {
		t.Fatalf("restart-from-db: echo2 = %d, want 200", dresp.StatusCode)
	}
}
