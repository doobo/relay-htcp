package admin

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	"relay-htcp/internal/config"
)

// tokenProvider is a server-like Provider whose ApplyConfigYAML actually
// updates the YAML, so token CRUD can be tested end to end without the tunnel.
type tokenProvider struct{ yaml string }

func (p *tokenProvider) Role() string   { return "server" }
func (p *tokenProvider) Status() Status { return Status{Role: "server"} }

func (p *tokenProvider) ValidateConfigYAML(y string) error {
	var cfg config.ServerConfig
	if err := yaml.Unmarshal([]byte(y), &cfg); err != nil {
		return err
	}
	return cfg.Validate()
}

func (p *tokenProvider) ApplyConfigYAML(y string) (SaveReport, error) {
	if err := p.ValidateConfigYAML(y); err != nil {
		return SaveReport{}, err
	}
	p.yaml = y
	return SaveReport{Applied: []string{"auth.tokens"}}, nil
}

func (p *tokenProvider) CurrentConfigYAML() string    { return p.yaml }
func (p *tokenProvider) ConfigFormSchema() FormSchema { return FormSchema{} }

const tokenTestYAML = `listen: ":5630"
auth:
    tokens:
        - name: a
          token: token-a
          routes: [ssh]
        - name: b
          token: token-b
          routes: [mysql]
routes:
    - name: ssh
      target: 127.0.0.1:22
    - name: mysql
      target: 127.0.0.1:3306
log:
    level: info
`

func newTokenEnv(t *testing.T) (*Server, *Store, *tokenProvider) {
	t.Helper()
	store := openTestStore(t)
	p := &tokenProvider{yaml: tokenTestYAML}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := NewServer(store, p, Options{Version: "test", SessionTTL: time.Hour, Token: "static"}, nil, log)
	return srv, store, p
}

func TestTokenListMasksSecrets(t *testing.T) {
	srv, _, _ := newTokenEnv(t)
	code, raw := doReq(t, srv, http.MethodGet, "/api/tokens", "static", nil)
	if code != http.StatusOK {
		t.Fatalf("list: %d %s", code, raw)
	}
	if strings.Contains(string(raw), "token-a") || strings.Contains(string(raw), "token-b") {
		t.Fatalf("token secret leaked: %s", raw)
	}
	var got tokenListResponse
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Tokens) != 2 || len(got.Routes) != 2 {
		t.Fatalf("list = %+v", got)
	}
	if got.Tokens[0].Name != "a" || len(got.Tokens[0].Routes) != 1 || got.Tokens[0].Routes[0] != "ssh" || !got.Tokens[0].TokenSet {
		t.Fatalf("row 0 = %+v", got.Tokens[0])
	}
	if got.Tokens[0].TokenHint != "…en-a" {
		t.Fatalf("hint = %q", got.Tokens[0].TokenHint)
	}
}

func TestTokenCreateUpdateDelete(t *testing.T) {
	srv, _, p := newTokenEnv(t)

	if code, raw := doReq(t, srv, http.MethodPost, "/api/tokens", "static",
		tokenRequest{Name: "new", Routes: []string{"ssh", "mysql"}}); code != http.StatusOK {
		t.Fatalf("create: %d %s", code, raw)
	} else if !strings.Contains(string(raw), `"token":"rhtcp_`) {
		t.Fatalf("create did not return the generated token: %s", raw)
	}
	var list tokenListResponse
	_, raw := doReq(t, srv, http.MethodGet, "/api/tokens", "static", nil)
	_ = json.Unmarshal(raw, &list)
	if len(list.Tokens) != 3 {
		t.Fatalf("after create = %+v", list.Tokens)
	}

	// Route must exist.
	if code, _ := doReq(t, srv, http.MethodPost, "/api/tokens", "static",
		tokenRequest{Name: "bad", Route: "nope"}); code != http.StatusBadRequest {
		t.Fatalf("unknown route create = %d", code)
	}

	// Update row 0: keep its token, bind multiple routes, disable it.
	enabled := false
	code, raw := doReq(t, srv, http.MethodPut, "/api/tokens/0", "static",
		tokenRequest{Name: "a2", Routes: []string{"ssh", "mysql"}, Enabled: &enabled})
	if code != http.StatusOK {
		t.Fatalf("update: %d %s", code, raw)
	}
	if !strings.Contains(p.yaml, "token-a") {
		t.Fatal("masked update dropped the stored token")
	}
	var cfg config.ServerConfig
	if err := yaml.Unmarshal([]byte(p.yaml), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Auth.Tokens[0].Name != "a2" || len(cfg.Auth.Tokens[0].Routes) != 2 || cfg.Auth.Tokens[0].On() {
		t.Fatalf("updated token = %+v", cfg.Auth.Tokens[0])
	}

	// Regenerate the token.
	_, raw = doReq(t, srv, http.MethodPut, "/api/tokens/0", "static",
		tokenRequest{Name: "a2", Routes: []string{"ssh", "mysql"}, Generate: true})
	if !strings.Contains(string(raw), `"token":"rhtcp_`) {
		t.Fatalf("regenerate did not return a token: %s", raw)
	}

	// Deleting the last remaining token is refused.
	if code, _ := doReq(t, srv, http.MethodDelete, "/api/tokens/2", "static", nil); code != http.StatusOK {
		t.Fatalf("delete before last = %d", code)
	}
	if code, _ := doReq(t, srv, http.MethodDelete, "/api/tokens/1", "static", nil); code != http.StatusOK {
		t.Fatalf("delete second = %d", code)
	}
	if code, _ := doReq(t, srv, http.MethodDelete, "/api/tokens/0", "static", nil); code != http.StatusBadRequest {
		t.Fatalf("deleting last token = %d, want 400", code)
	}
}

func TestTokenDisabledIsNotBuilt(t *testing.T) {
	var cfg config.ServerConfig
	if err := yaml.Unmarshal([]byte(tokenTestYAML), &cfg); err != nil {
		t.Fatal(err)
	}
	off := false
	cfg.Auth.Tokens[0].Enabled = &off
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Auth.Tokens[0].On() {
		t.Fatal("disabled token reports On()")
	}
}
