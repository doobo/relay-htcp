package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeProvider is a Provider test double.
type fakeProvider struct {
	role        string
	validYAML   string
	applyErr    error
	currentYAML string
	appliedYAML string
	validateFn  func(string) error
	applyErrFn  func(string) error
}

func (f *fakeProvider) Role() string { return f.role }

func (f *fakeProvider) Status() Status {
	st := Status{Role: f.role}
	if f.role == "server" {
		st.Server = &ServerStatus{ListenAddr: ":8443", TLS: true, ActiveTunnels: 1,
			BytesIn: 100, BytesOut: 200, DecoyViews: 3}
	} else {
		st.Client = &ClientStatus{ServerAddr: "https://x",
			Slots: []SlotStat{{Index: 0, State: SlotStateConnected}}}
	}
	return st
}

func (f *fakeProvider) ValidateConfigYAML(y string) error {
	if f.validateFn != nil {
		return f.validateFn(y)
	}
	if strings.TrimSpace(y) == "" {
		return os.ErrInvalid
	}
	return nil
}

func (f *fakeProvider) ApplyConfigYAML(y string) (SaveReport, error) {
	f.appliedYAML = y
	if f.applyErrFn != nil {
		return SaveReport{}, f.applyErrFn(y)
	}
	if f.applyErr != nil {
		return SaveReport{}, f.applyErr
	}
	return SaveReport{Applied: []string{"routes"}}, nil
}

func (f *fakeProvider) CurrentConfigYAML() string {
	if f.currentYAML != "" {
		return f.currentYAML
	}
	return "listen: \":8443\"\nauth:\n  token: super-secret\n"
}

func (f *fakeProvider) ConfigFormSchema() FormSchema {
	return FormSchema{Sections: []FormSection{{
		Title: "基本",
		Fields: []FormField{
			{Path: "listen", Label: "监听地址", Type: FormText},
			{Path: "auth.token", Label: "Token", Type: FormSecret},
		},
	}}}
}

type testEnv struct {
	store  *Store
	srv    *Server
	fake   *fakeProvider
	admin  User
	viewer User
	token  string // admin session token
}

func setupEnv(t *testing.T) *testEnv {
	t.Helper()
	return setupEnvWith(t, Options{})
}

func setupEnvWith(t *testing.T, opts Options) *testEnv {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if err := store.Migrate(); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	fake := &fakeProvider{role: "server"}
	if opts.Version == "" {
		opts.Version = "test"
	}
	if opts.SessionTTL == 0 {
		opts.SessionTTL = time.Hour
	}
	srv := NewServer(store, fake, opts, nil, log)

	adminHash, _ := HashPassword("adminpass1")
	admin, err := store.CreateUser("admin", adminHash, RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	viewerHash, _ := HashPassword("viewerpass1")
	viewer, err := store.CreateUser("viewer", viewerHash, RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	return &testEnv{store: store, srv: srv, fake: fake, admin: admin, viewer: viewer}
}

func login(t *testing.T, srv *Server, username, password string) (int, loginResponse) {
	t.Helper()
	body, _ := json.Marshal(loginRequest{Username: username, Password: password})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	var lr loginResponse
	if w.Code == http.StatusOK {
		_ = json.Unmarshal(w.Body.Bytes(), &lr)
	}
	return w.Code, lr
}

func doReq(t *testing.T, srv *Server, method, path, token string, body any) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w.Code, w.Body.Bytes()
}

func TestLoginFlow(t *testing.T) {
	env := setupEnv(t)
	srv := env.srv

	code, _ := login(t, srv, "admin", "wrongpass")
	if code != http.StatusUnauthorized {
		t.Fatalf("wrong password: got %d", code)
	}
	code, _ = login(t, srv, "nobody", "whatever1")
	if code != http.StatusUnauthorized {
		t.Fatalf("unknown user: got %d", code)
	}

	code, lr := login(t, srv, "admin", "adminpass1")
	if code != http.StatusOK || lr.Token == "" || lr.User.Username != "admin" {
		t.Fatalf("login = %d %+v", code, lr)
	}
	env.token = lr.Token

	// Session works on a protected endpoint.
	code, _ = doReq(t, srv, http.MethodGet, "/api/auth/me", lr.Token, nil)
	if code != http.StatusOK {
		t.Fatalf("me with session: %d", code)
	}
	// No token.
	code, _ = doReq(t, srv, http.MethodGet, "/api/auth/me", "", nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("me without token: %d", code)
	}
	// Logout revokes.
	code, _ = doReq(t, srv, http.MethodPost, "/api/auth/logout", lr.Token, nil)
	if code != http.StatusNoContent {
		t.Fatalf("logout: %d", code)
	}
	code, _ = doReq(t, srv, http.MethodGet, "/api/auth/me", lr.Token, nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("after logout: %d", code)
	}
}

func TestRestartEndpoint(t *testing.T) {
	called := make(chan struct{}, 1)
	env := setupEnvWith(t, Options{Restart: func() {
		select {
		case called <- struct{}{}:
		default:
		}
	}})
	_, lr := login(t, env.srv, "admin", "adminpass1")
	code, body := doReq(t, env.srv, http.MethodPost, "/api/restart", lr.Token, nil)
	if code != http.StatusOK {
		t.Fatalf("restart = %d %s", code, body)
	}
	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("restart callback was not invoked")
	}

	// Viewers cannot restart.
	_, vr := login(t, env.srv, "viewer", "viewerpass1")
	if code, _ := doReq(t, env.srv, http.MethodPost, "/api/restart", vr.Token, nil); code != http.StatusForbidden {
		t.Fatalf("viewer restart = %d, want 403", code)
	}

	// Roles without restart support report 501.
	plain := setupEnv(t)
	_, pr := login(t, plain.srv, "admin", "adminpass1")
	if code, _ := doReq(t, plain.srv, http.MethodPost, "/api/restart", pr.Token, nil); code != http.StatusNotImplemented {
		t.Fatalf("unsupported restart = %d, want 501", code)
	}
}

func TestDisabledUserRejected(t *testing.T) {
	env := setupEnv(t)
	if err := env.store.UpdateUserEnabled(env.admin.ID, false); err != nil {
		t.Fatal(err)
	}
	code, _ := login(t, env.srv, "admin", "adminpass1")
	if code != http.StatusUnauthorized {
		t.Fatalf("disabled user login: %d", code)
	}
}

func TestRateLimit(t *testing.T) {
	store, _ := Open(filepath.Join(t.TempDir(), "rl.db"))
	t.Cleanup(func() { store.Close() })
	if err := store.Migrate(); err != nil {
		t.Fatal(err)
	}
	h, _ := HashPassword("adminpass1")
	if _, err := store.CreateUser("admin", h, RoleAdmin); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := NewServer(store, &fakeProvider{}, Options{
		Version: "test", RateLimit: 3, RateWindow: time.Minute,
	}, nil, log)

	for i := 0; i < 3; i++ {
		code, _ := login(t, srv, "admin", "nope")
		if code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i+1, code)
		}
	}
	code, _ := login(t, srv, "admin", "adminpass1")
	if code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", code)
	}
}

func TestStaticToken(t *testing.T) {
	env := setupEnv(t)
	srv := NewServer(env.store, &fakeProvider{},
		Options{Version: "test", Token: "bootstrap-secret"}, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	code, _ := doReq(t, srv, http.MethodGet, "/api/auth/me", "bootstrap-secret", nil)
	if code != http.StatusOK {
		t.Fatalf("static token me: %d", code)
	}
	code, _ = doReq(t, srv, http.MethodGet, "/api/auth/me", "other", nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("wrong static token: %d", code)
	}
}

func TestRoleEnforcement(t *testing.T) {
	env := setupEnv(t)
	srv := env.srv

	_, lr := login(t, srv, "viewer", "viewerpass1")
	code, _ := doReq(t, srv, http.MethodGet, "/api/status", lr.Token, nil)
	if code != http.StatusOK {
		t.Fatalf("viewer status: %d", code)
	}
	// Raw YAML contains cleartext client tokens: viewers must not read it.
	if code, _ := doReq(t, srv, http.MethodGet, "/api/config", lr.Token, nil); code != http.StatusForbidden {
		t.Fatalf("viewer get config yaml: %d, want 403", code)
	}
	code, _ = doReq(t, srv, http.MethodPut, "/api/config", lr.Token,
		configRequest{YAML: "listen: \":1\""})
	if code != http.StatusForbidden {
		t.Fatalf("viewer put config: %d", code)
	}
	code, _ = doReq(t, srv, http.MethodPost, "/api/users", lr.Token,
		createUserRequest{Username: "x", Password: "longenough"})
	if code != http.StatusForbidden {
		t.Fatalf("viewer create user: %d", code)
	}
}

func TestStatusEndpoint(t *testing.T) {
	env := setupEnv(t)
	_, lr := login(t, env.srv, "admin", "adminpass1")
	code, raw := doReq(t, env.srv, http.MethodGet, "/api/status", lr.Token, nil)
	if code != http.StatusOK {
		t.Fatalf("status: %d", code)
	}
	var st Status
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	if st.Role != "server" || st.Version != "test" || st.Server == nil {
		t.Fatalf("status = %+v", st)
	}
	if st.Server.DecoyViews != 3 || len(st.Server.ActiveStreams) != 0 {
		t.Fatalf("server status = %+v", st.Server)
	}
}

func TestConfigFlow(t *testing.T) {
	env := setupEnv(t)
	_, lr := login(t, env.srv, "admin", "adminpass1")

	code, raw := doReq(t, env.srv, http.MethodGet, "/api/config", lr.Token, nil)
	if code != http.StatusOK {
		t.Fatalf("get config: %d", code)
	}
	var got struct{ YAML, Source string }
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Source != "file" || !strings.Contains(got.YAML, "8443") {
		t.Fatalf("config = %+v", got)
	}

	code, raw = doReq(t, env.srv, http.MethodPut, "/api/config", lr.Token,
		configRequest{YAML: "listen: \":9999\""})
	if code != http.StatusOK {
		t.Fatalf("put config: %d %s", code, raw)
	}
	// Persisted to the store.
	stored, err := env.store.GetSetting(ConfigKey)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stored, "8443") {
		t.Fatalf("stored = %q", stored)
	}

	// Invalid config rejected, not persisted.
	code, _ = doReq(t, env.srv, http.MethodPut, "/api/config", lr.Token,
		configRequest{YAML: ""})
	if code != http.StatusBadRequest {
		t.Fatalf("empty yaml: %d", code)
	}
}

func TestConfigFormAPI(t *testing.T) {
	env := setupEnv(t)
	_, lr := login(t, env.srv, "admin", "adminpass1")

	code, raw := doReq(t, env.srv, http.MethodGet, "/api/config/form", lr.Token, nil)
	if code != http.StatusOK {
		t.Fatalf("get form: %d %s", code, raw)
	}
	if strings.Contains(string(raw), "super-secret") {
		t.Fatalf("form response leaked a secret: %s", raw)
	}
	var form ConfigForm
	if err := json.Unmarshal(raw, &form); err != nil {
		t.Fatal(err)
	}
	if form.Role != "server" || len(form.Sections) == 0 || form.Values["listen"] != ":8443" {
		t.Fatalf("form = %+v", form)
	}
	if form.Values["auth.token"] != "" {
		t.Fatalf("secret not masked: %v", form.Values["auth.token"])
	}

	// Viewer may read but not write.
	_, vr := login(t, env.srv, "viewer", "viewerpass1")
	code, _ = doReq(t, env.srv, http.MethodPut, "/api/config/form", vr.Token,
		map[string]any{"values": map[string]any{"listen": ":1"}})
	if code != http.StatusForbidden {
		t.Fatalf("viewer put form: %d", code)
	}

	// Submitting the masked secret must keep the stored one.
	code, raw = doReq(t, env.srv, http.MethodPut, "/api/config/form", lr.Token,
		map[string]any{"values": map[string]any{"listen": ":9999", "auth.token": ""}})
	if code != http.StatusOK {
		t.Fatalf("put form: %d %s", code, raw)
	}
	if !strings.Contains(env.fake.appliedYAML, ":9999") {
		t.Fatalf("listen not applied: %s", env.fake.appliedYAML)
	}
	if !strings.Contains(env.fake.appliedYAML, "super-secret") {
		t.Fatalf("masked secret not preserved: %s", env.fake.appliedYAML)
	}
}

func TestAdminHandlerPrefix(t *testing.T) {
	env := setupEnv(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ui := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ui:"+r.URL.Path)
	})
	srv := NewServer(env.store, env.fake, Options{
		Version: "test", SessionTTL: time.Hour, Path: "/manage-x/",
	}, ui, log)
	h := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/manage-x", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("/manage-x = %d, want 307", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/manage-x/" {
		t.Fatalf("redirect location = %q", loc)
	}

	// The standalone listener root is the panel front page: it lands on the
	// login view rather than a 404.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("GET / = %d, want 307", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/manage-x/" {
		t.Fatalf("root redirect location = %q", loc)
	}

	for path, want := range map[string]string{
		"/manage-x/":           "ui:/",
		"/manage-x/app.js":     "ui:/app.js",
		"/manage-x/api/status": "", // handled by the API mux, not the UI
	} {
		req = httptest.NewRequest(http.MethodGet, path, nil)
		w = httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if want != "" && w.Body.String() != want {
			t.Fatalf("%s = %q, want %q", path, w.Body.String(), want)
		}
	}

	body, _ := json.Marshal(loginRequest{Username: "admin", Password: "adminpass1"})
	req = httptest.NewRequest(http.MethodPost, "/manage-x/api/auth/login", bytes.NewReader(body))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login under prefix = %d %s", w.Code, w.Body.String())
	}

	// The unprefixed API must not be reachable any more.
	req = httptest.NewRequest(http.MethodGet, "/api/status", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unprefixed API = %d, want 404", w.Code)
	}
}

func TestAdminAllowlist(t *testing.T) {
	al, err := ParseIPAllowlist([]string{"127.0.0.0/8", "::1/128"})
	if err != nil {
		t.Fatal(err)
	}
	env := setupEnv(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := NewServer(env.store, env.fake, Options{
		Version: "test", SessionTTL: time.Hour, Path: "/admin", Allowlist: al,
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), log)
	h := srv.Handler()

	for addr, want := range map[string]int{
		"203.0.113.9:1234":     http.StatusForbidden,
		"127.0.0.1:1234":       http.StatusOK,
		"[::1]:1234":           http.StatusOK,
		"[::ffff:127.0.0.1]:1": http.StatusOK,
	} {
		req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
		req.RemoteAddr = addr
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("remote %s = %d, want %d", addr, w.Code, want)
		}
	}

	if _, err := ParseIPAllowlist([]string{"not-a-cidr"}); err == nil {
		t.Fatal("invalid CIDR accepted")
	}
}

func TestUserAPI(t *testing.T) {
	env := setupEnv(t)
	_, lr := login(t, env.srv, "admin", "adminpass1")

	// Create.
	code, raw := doReq(t, env.srv, http.MethodPost, "/api/users", lr.Token,
		createUserRequest{Username: "carol", Password: "carolpass1", Role: "viewer"})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, raw)
	}
	var carol UserSummary
	if err := json.Unmarshal(raw, &carol); err != nil {
		t.Fatal(err)
	}

	// Weak password rejected.
	code, _ = doReq(t, env.srv, http.MethodPost, "/api/users", lr.Token,
		createUserRequest{Username: "dave", Password: "short"})
	if code != http.StatusBadRequest {
		t.Fatalf("weak password: %d", code)
	}

	// Last admin cannot be demoted or deleted.
	code, _ = doReq(t, env.srv, http.MethodPut, "/api/users", lr.Token,
		map[string]any{"id": env.admin.ID, "role": "viewer"})
	_ = code
	code, _ = doReq(t, env.srv, http.MethodPut, "/api/users/"+itoa(env.admin.ID), lr.Token,
		map[string]any{"role": "viewer"})
	if code != http.StatusBadRequest {
		t.Fatalf("demote last admin: %d", code)
	}
	code, _ = doReq(t, env.srv, http.MethodDelete, "/api/users/"+itoa(env.admin.ID), lr.Token, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("delete last admin: %d", code)
	}

	// Password change revokes the user's sessions.
	_, vlr := login(t, env.srv, "carol", "carolpass1")
	code, _ = doReq(t, env.srv, http.MethodPut, "/api/users/"+itoa(carol.ID), lr.Token,
		map[string]any{"password": "newpassword1"})
	if code != http.StatusOK {
		t.Fatalf("password change: %d", code)
	}
	code, _ = doReq(t, env.srv, http.MethodGet, "/api/auth/me", vlr.Token, nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("old session still valid: %d", code)
	}

	// Delete the viewer user.
	code, _ = doReq(t, env.srv, http.MethodDelete, "/api/users/"+itoa(carol.ID), lr.Token, nil)
	if code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}
