package tunnel

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"relay-htcp/internal/admin"
	"relay-htcp/internal/config"
)

func yamlPath(doc map[string]any, path string) (any, bool) {
	var cur any = doc
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// TestConfigFormSchemaMatchesYAML guards the panel schema against typos: every
// declared path must exist in the canonical config and every table column must
// exist on its rows. This is what keeps the structured editor in sync as
// tunables are added.
func TestConfigFormSchemaMatchesYAML(t *testing.T) {
	srv := newSwapTestServer(t)

	ccfg := &config.ClientConfig{
		Server:    "http://127.0.0.1:1",
		Auth:      config.ClientAuth{Token: "token"},
		Listeners: []config.Listener{{Local: "127.0.0.1:0", Target: "ssh"}},
		Providers: []config.Provider{{Route: "ssh-stcp", Local: "127.0.0.1:2", Servers: []string{"default"}}},
	}
	if err := ccfg.Validate(); err != nil {
		t.Fatal(err)
	}
	pool, err := NewPool(ccfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	for name, p := range map[string]admin.Provider{"server": srv, "client": pool} {
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(p.CurrentConfigYAML()), &doc); err != nil {
			t.Fatalf("%s: current yaml: %v", name, err)
		}
		schema := p.ConfigFormSchema()
		if len(schema.Sections) == 0 {
			t.Fatalf("%s: empty schema", name)
		}
		for _, sec := range schema.Sections {
			for _, f := range sec.Fields {
				v, ok := yamlPath(doc, f.Path)
				if !ok {
					t.Errorf("%s: schema path %q missing from current config", name, f.Path)
					continue
				}
				if f.Type != admin.FormTable {
					continue
				}
				rows, _ := v.([]any)
				if len(rows) == 0 {
					t.Errorf("%s: table %q has no rows to check", name, f.Path)
					continue
				}
				row, _ := rows[0].(map[string]any)
				for _, col := range f.Columns {
					if _, ok := row[col.Path]; !ok {
						// Optional bool cells may be omitted (unset = false).
						if col.Type == admin.FormBool {
							continue
						}
						t.Errorf("%s: table %q column %q missing", name, f.Path, col.Path)
					}
				}
			}
		}
	}
}

// TestClientListenerServersDropdown pins the widget used for listener ->
// servers: a dropdown multi-select populated with the configured servers.
func TestClientListenerServersDropdown(t *testing.T) {
	cfg := &config.ClientConfig{
		Auth: config.ClientAuth{Token: "token"},
		Servers: []config.ServerEndpoint{
			{Name: "primary", URL: "http://127.0.0.1:1"},
			{Name: "backup", URL: "http://127.0.0.1:2"},
		},
		Listeners: []config.Listener{{Local: "127.0.0.1:0", Target: "ssh"}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	pool, err := NewPool(cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	var col admin.FormField
	for _, sec := range pool.ConfigFormSchema().Sections {
		for _, f := range sec.Fields {
			if f.Path != "listeners" {
				continue
			}
			for _, c := range f.Columns {
				if c.Path == "servers" {
					col = c
				}
			}
		}
	}
	if col.Type != admin.FormMultiSelect {
		t.Fatalf("listeners.servers type = %q, want %q", col.Type, admin.FormMultiSelect)
	}
	if strings.Join(col.Options, ",") != "primary,backup" {
		t.Fatalf("listeners.servers options = %v", col.Options)
	}
}
