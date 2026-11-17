package config

import (
	"path/filepath"
	"strings"
	"time"
)

// AdminConfig configures the embedded admin panel. When Disabled (the
// default) no admin port is opened and no database is touched.
type AdminConfig struct {
	Enabled bool `yaml:"enabled"`
	// Shared mounts the panel on the tunnel listener instead of opening a
	// second port. This is the preferred mode for the public server: external
	// observers only see one web service.
	Shared bool `yaml:"shared"`
	// Path is the URL prefix of the panel, e.g. "/admin". In shared mode it
	// also acts as a cheap obscurity layer; pick something unguessable.
	Path string `yaml:"path"`
	// AllowedCIDRs restricts who may reach the panel. Empty means no IP
	// restriction; shared mode defaults to all addresses (tighten it in the
	// panel's IP Access page or here).
	AllowedCIDRs    []string      `yaml:"allowed_cidrs"`
	Listen          string        `yaml:"listen"`   // standalone mode only
	Token           string        `yaml:"token"`    // optional static bootstrap token
	DBPath          string        `yaml:"db_path"`  // SQLite database file
	KeyFile         string        `yaml:"key_file"` // master key file for at-rest encryption
	DefaultUsername string        `yaml:"default_username"`
	DefaultPassword string        `yaml:"default_password"`
	SessionTTL      time.Duration `yaml:"session_ttl"`
}

// finalize applies defaults to the admin section.
func (a *AdminConfig) finalize() {
	if a.Listen == "" {
		a.Listen = "127.0.0.1:8080"
	}
	if a.DBPath == "" {
		a.DBPath = filepath.Join("data", "admin.db")
	}
	if a.KeyFile == "" {
		a.KeyFile = a.DBPath + ".key"
	}
	if a.DefaultUsername == "" {
		a.DefaultUsername = "admin"
	}
	if a.SessionTTL <= 0 {
		a.SessionTTL = 24 * time.Hour
	}
	a.Path = normalizeAdminPath(a.Path, a.Shared)
	if a.Shared && len(a.AllowedCIDRs) == 0 {
		// Default-open: the login is still protected by password + encrypted
		// login, and the panel's IP Access page can tighten this at runtime.
		a.AllowedCIDRs = []string{"0.0.0.0/0", "::/0"}
	}
}

// normalizeAdminPath turns "" into "/admin" in shared mode (root would hide
// the decoy page and shadow tunnel handling) and "/" in standalone mode, then
// strips trailing slashes.
func normalizeAdminPath(p string, shared bool) string {
	p = strings.TrimSpace(p)
	if p == "" {
		if shared {
			return "/admin"
		}
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimRight(p, "/")
	if p == "" {
		return "/"
	}
	return p
}
