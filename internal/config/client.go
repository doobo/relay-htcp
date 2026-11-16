package config

import (
	"fmt"
	"net/url"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// ClientConfig is the client side configuration.
type ClientConfig struct {
	Server    string         `yaml:"server"` // e.g. https://tunnel.example.com:443
	TLS       ClientTLS      `yaml:"tls"`
	Auth      ClientAuth     `yaml:"auth"`
	Listeners []Listener     `yaml:"listeners"`
	Tunnel    TunnelClient   `yaml:"tunnel"`
	Disguise  ClientDisguise `yaml:"disguise"`
	Log       LogConfig      `yaml:"log"`
	Admin     AdminConfig    `yaml:"admin"`
}

// ClientTLS tunes the client's TLS behaviour.
type ClientTLS struct {
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	CAFile             string `yaml:"ca_file"`
}

// ClientAuth carries the authentication token.
type ClientAuth struct {
	Token string `yaml:"token"`
}

// Listener maps a local port to a server-side route.
type Listener struct {
	Local  string `yaml:"local"`
	Target string `yaml:"target"`
}

// TunnelClient tunes the client tunnel pool.
type TunnelClient struct {
	Connections   int           `yaml:"connections"`
	Heartbeat     time.Duration `yaml:"heartbeat"`
	HeartbeatMiss int           `yaml:"heartbeat_miss"`
	ReconnectMin  time.Duration `yaml:"reconnect_min"`
	ReconnectMax  time.Duration `yaml:"reconnect_max"`
	StreamTimeout time.Duration `yaml:"stream_timeout"`
}

// ClientDisguise controls whether the client sends browser-like headers.
// Enabled defaults to true when unset.
type ClientDisguise struct {
	Enabled   *bool  `yaml:"enabled"`
	UserAgent string `yaml:"user_agent"`
}

// On reports whether camouflage headers are sent (default true).
func (d ClientDisguise) On() bool { return d.Enabled == nil || *d.Enabled }

// LoadClient reads and validates a client configuration file.
func LoadClient(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg ClientConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks the configuration and applies defaults.
func (c *ClientConfig) Validate() error {
	u, err := url.Parse(c.Server)
	if err != nil {
		return fmt.Errorf("server: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("server: must be scheme://host[:port] without a path, got %q", c.Server)
	}
	if c.Auth.Token == "" {
		return fmt.Errorf("auth.token: required")
	}
	if len(c.Listeners) == 0 {
		return fmt.Errorf("listeners: at least one required")
	}
	seen := map[string]bool{}
	for i, l := range c.Listeners {
		if l.Local == "" || l.Target == "" {
			return fmt.Errorf("listeners[%d]: local and target are required", i)
		}
		if seen[l.Local] {
			return fmt.Errorf("listeners: duplicate local address %q", l.Local)
		}
		seen[l.Local] = true
	}
	if c.Tunnel.Connections <= 0 {
		c.Tunnel.Connections = 2
	}
	if c.Tunnel.Heartbeat <= 0 {
		c.Tunnel.Heartbeat = 15 * time.Second
	}
	if c.Tunnel.HeartbeatMiss <= 0 {
		c.Tunnel.HeartbeatMiss = 3
	}
	if c.Tunnel.ReconnectMin <= 0 {
		c.Tunnel.ReconnectMin = time.Second
	}
	if c.Tunnel.ReconnectMax <= 0 {
		c.Tunnel.ReconnectMax = 30 * time.Second
	}
	if c.Tunnel.ReconnectMax < c.Tunnel.ReconnectMin {
		c.Tunnel.ReconnectMax = c.Tunnel.ReconnectMin
	}
	if c.Tunnel.StreamTimeout <= 0 {
		c.Tunnel.StreamTimeout = 30 * time.Second
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Disguise.Enabled == nil {
		c.Disguise.Enabled = boolPtr(true)
	}
	c.Admin.finalize()
	if c.Admin.Shared {
		return fmt.Errorf("admin.shared: only supported on the server")
	}
	return nil
}
