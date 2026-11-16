package admin

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type formProvider struct {
	yaml   string
	schema FormSchema
}

func (p *formProvider) Role() string                               { return "server" }
func (p *formProvider) Status() Status                             { return Status{} }
func (p *formProvider) ValidateConfigYAML(string) error            { return nil }
func (p *formProvider) ApplyConfigYAML(string) (SaveReport, error) { return SaveReport{}, nil }
func (p *formProvider) CurrentConfigYAML() string                  { return p.yaml }
func (p *formProvider) ConfigFormSchema() FormSchema               { return p.schema }

const formTestYAML = `listen: ":8443"
auth:
  token: scalar-secret
  tokens:
    - name: a
      token: row-a-secret
      routes: [ssh]
    - name: b
      token: row-b-secret
routes:
  - name: ssh
    target: "127.0.0.1:22"
`

func formTestProvider() *formProvider {
	return &formProvider{
		yaml: formTestYAML,
		schema: FormSchema{Sections: []FormSection{
			{
				Title: "连接",
				Fields: []FormField{
					{Path: "listen", Label: "监听地址", Type: FormText},
					{Path: "auth.token", Label: "认证 Token", Type: FormSecret},
					{Path: "tunnel.connections", Label: "连接池", Type: FormNumber},
					{Path: "disguise.enabled", Label: "伪装", Type: FormBool},
				},
			},
			{
				Title: "Token",
				Fields: []FormField{{
					Path: "auth.tokens", Label: "Token 列表", Type: FormTable,
					Columns: []FormField{
						{Path: "name", Label: "名称", Type: FormText},
						{Path: "token", Label: "Token", Type: FormSecret},
						{Path: "routes", Label: "允许路由", Type: FormCSV},
					},
				}},
			},
		}},
	}
}

func TestBuildConfigFormMasksSecrets(t *testing.T) {
	p := formTestProvider()
	form, err := buildConfigForm(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := form.Values["listen"]; got != ":8443" {
		t.Fatalf("listen = %v", got)
	}
	if got, _ := form.Values["auth.token"].(string); got != "" {
		t.Fatalf("scalar secret leaked: %q", got)
	}
	rows, ok := form.Values["auth.tokens"].([]any)
	if !ok || len(rows) != 2 {
		t.Fatalf("token rows = %v", form.Values["auth.tokens"])
	}
	first := rows[0].(map[string]any)
	if first["token"] != "" {
		t.Fatalf("row secret leaked: %v", first["token"])
	}
	if first["name"] != "a" || first["routes"] != "ssh" {
		t.Fatalf("row values = %v", first)
	}
	if first["_id"] != 0 || rows[1].(map[string]any)["_id"] != 1 {
		t.Fatalf("row ids missing: %v", rows)
	}
}

func TestApplyConfigFormKeepsMaskedSecrets(t *testing.T) {
	p := formTestProvider()
	values := map[string]any{
		"listen":             ":9443",
		"auth.token":         "",
		"tunnel.connections": "4",
		"disguise.enabled":   true,
		"auth.tokens": []any{
			map[string]any{"_id": float64(0), "name": "a", "token": "", "routes": "ssh, mysql"},
			map[string]any{"_id": float64(1), "name": "b", "token": "new-b", "routes": ""},
			map[string]any{"_id": float64(-1), "name": "c", "token": "new-c", "routes": "ssh"},
		},
	}
	out, err := applyConfigForm(p, values)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Listen string
		Auth   struct {
			Token  string
			Tokens []struct {
				Name   string
				Token  string
				Routes []string
			}
		}
		Tunnel   struct{ Connections int }
		Disguise struct{ Enabled bool }
	}
	if err := yaml.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("unmarshal result: %v\n%s", err, out)
	}
	if got.Listen != ":9443" || got.Tunnel.Connections != 4 || !got.Disguise.Enabled {
		t.Fatalf("scalars = %+v", got)
	}
	if got.Auth.Token != "scalar-secret" {
		t.Fatalf("scalar secret not kept: %q", got.Auth.Token)
	}
	if len(got.Auth.Tokens) != 3 {
		t.Fatalf("rows = %+v", got.Auth.Tokens)
	}
	if got.Auth.Tokens[0].Token != "row-a-secret" {
		t.Fatalf("row 0 secret not kept: %q", got.Auth.Tokens[0].Token)
	}
	if got.Auth.Tokens[1].Token != "new-b" {
		t.Fatalf("row 1 secret not replaced: %q", got.Auth.Tokens[1].Token)
	}
	if got.Auth.Tokens[2].Token != "new-c" {
		t.Fatalf("new row secret = %q", got.Auth.Tokens[2].Token)
	}
	if strings.Join(got.Auth.Tokens[0].Routes, ",") != "ssh,mysql" {
		t.Fatalf("csv routes = %v", got.Auth.Tokens[0].Routes)
	}
	if len(got.Auth.Tokens[1].Routes) != 0 {
		t.Fatalf("empty csv = %v", got.Auth.Tokens[1].Routes)
	}
}

func TestApplyConfigFormRejectsBadDuration(t *testing.T) {
	p := formTestProvider()
	p.schema.Sections[0].Fields = append(p.schema.Sections[0].Fields,
		FormField{Path: "tunnel.dial_timeout", Label: "拨号超时", Type: FormDuration})
	if _, err := applyConfigForm(p, map[string]any{"tunnel.dial_timeout": "soon"}); err == nil {
		t.Fatal("invalid duration accepted")
	}
	if _, err := applyConfigForm(p, map[string]any{"tunnel.dial_timeout": ""}); err != nil {
		t.Fatalf("empty duration should keep the old value: %v", err)
	}
}
