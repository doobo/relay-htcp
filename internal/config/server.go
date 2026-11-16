// Package config parses relay-htcp YAML configuration files.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ServerConfig is the server side configuration.
type ServerConfig struct {
	Listen   string         `yaml:"listen"`
	TLS      TLSConfig      `yaml:"tls"`
	Auth     AuthConfig     `yaml:"auth"`
	Routes   []Route        `yaml:"routes"`
	Tunnel   TunnelServer   `yaml:"tunnel"`
	Disguise DisguiseConfig `yaml:"disguise"`
	Log      LogConfig      `yaml:"log"`
	Admin    AdminConfig    `yaml:"admin"`

	routeTable map[string]string // name -> target, built by Validate
}

// TLSConfig configures the TLS listener. When Cert and Key are empty the
// server listens in cleartext (h2c), meant for LAN use and tests.
type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

// Enabled reports whether TLS is configured.
func (t TLSConfig) Enabled() bool { return t.Cert != "" && t.Key != "" }

// Token is one authenticated client identity.
type Token struct {
	Name   string   `yaml:"name"`
	Token  string   `yaml:"token"`
	Routes []string `yaml:"routes,omitempty"` // empty means all routes are allowed
}

// AuthConfig holds all accepted tokens.
type AuthConfig struct {
	Tokens []Token `yaml:"tokens"`
}

// Route maps a logical name to a local target address.
type Route struct {
	Name   string `yaml:"name"`
	Target string `yaml:"target"`
}

// TunnelServer tunes server-side tunnel behaviour.
type TunnelServer struct {
	MaxConcurrentStreams int           `yaml:"max_concurrent_streams"`
	MaxConnections       int           `yaml:"max_connections"`
	DialTimeout          time.Duration `yaml:"dial_timeout"`
	IdleTimeout          time.Duration `yaml:"idle_timeout"`
}

// DisguiseConfig toggles camouflage behaviour. Enabled defaults to true.
type DisguiseConfig struct {
	Enabled *bool `yaml:"enabled"`
}

// On reports whether camouflage is enabled (default true).
func (d DisguiseConfig) On() bool { return d.Enabled == nil || *d.Enabled }

// LogConfig configures logging.
type LogConfig struct {
	Level string `yaml:"level"`
}

// LoadServer reads and validates a server configuration file.
func LoadServer(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg ServerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks the configuration, applies defaults and fills derived
// state.
func (c *ServerConfig) Validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen: required")
	}
	if len(c.Auth.Tokens) == 0 {
		return fmt.Errorf("auth.tokens: at least one token required")
	}
	seen := map[string]bool{}
	for _, t := range c.Auth.Tokens {
		if t.Token == "" {
			return fmt.Errorf("auth.tokens: empty token value (name=%q)", t.Name)
		}
		if seen[t.Token] {
			return fmt.Errorf("auth.tokens: duplicate token (name=%q)", t.Name)
		}
		seen[t.Token] = true
	}
	if len(c.Routes) == 0 {
		return fmt.Errorf("routes: at least one route required")
	}
	c.routeTable = make(map[string]string, len(c.Routes))
	seenRoutes := map[string]bool{}
	for _, r := range c.Routes {
		if r.Name == "" || r.Target == "" {
			return fmt.Errorf("routes: name and target are required")
		}
		if seenRoutes[r.Name] {
			return fmt.Errorf("routes: duplicate name %q", r.Name)
		}
		seenRoutes[r.Name] = true
		c.routeTable[r.Name] = r.Target
	}
	if c.Tunnel.MaxConcurrentStreams <= 0 {
		c.Tunnel.MaxConcurrentStreams = 128
	}
	if c.Tunnel.DialTimeout <= 0 {
		c.Tunnel.DialTimeout = 10 * time.Second
	}
	if c.Tunnel.IdleTimeout <= 0 {
		c.Tunnel.IdleTimeout = 90 * time.Second
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Disguise.Enabled == nil {
		c.Disguise.Enabled = boolPtr(true)
	}
	c.Admin.finalize()
	if c.Admin.Enabled && c.Admin.Shared {
		if c.Admin.Path == "/" {
			return fmt.Errorf("admin.path: cannot be / when admin.shared is enabled")
		}
		for _, reserved := range []string{"/tunnel", "/stream", "/health"} {
			if c.Admin.Path == reserved || strings.HasPrefix(reserved, c.Admin.Path+"/") {
				return fmt.Errorf("admin.path: %q conflicts with tunnel endpoint %s", c.Admin.Path, reserved)
			}
		}
	}
	return nil
}

func boolPtr(v bool) *bool { return &v }

// RouteTarget returns the local target for a route name.
func (c *ServerConfig) RouteTarget(name string) (string, bool) {
	t, ok := c.routeTable[name]
	return t, ok
}
