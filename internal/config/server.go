// Package config parses relay-htcp YAML configuration files.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
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
	Proxy    ProxyConfig    `yaml:"proxy"`
	Tunnel   TunnelServer   `yaml:"tunnel"`
	Disguise DisguiseConfig `yaml:"disguise"`
	Log      LogConfig      `yaml:"log"`
	Admin    AdminConfig    `yaml:"admin"`

	routeTable map[string]string // name -> target, built by Validate
	routeProxy map[string]bool   // name -> use_proxy, built by Validate
	routeType  map[string]string // name -> tcp|stcp, built by Validate
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
	Routes []string `yaml:"routes,omitempty"` // zero or more routes; empty means all
	// Enabled defaults to true. A disabled token is kept in the config but
	// never authenticates.
	Enabled *bool `yaml:"enabled,omitempty"`
	// Traffic limits in MB per calendar day/week/month. Zero means unlimited.
	// LimitEnabled turns the runtime quota switch on; a background task
	// recomputes the blocked state from the daily traffic table.
	LimitEnabled   bool  `yaml:"limit_enabled,omitempty"`
	DailyLimitMB   int64 `yaml:"daily_limit_mb,omitempty"`
	WeeklyLimitMB  int64 `yaml:"weekly_limit_mb,omitempty"`
	MonthlyLimitMB int64 `yaml:"monthly_limit_mb,omitempty"`
}

// On reports whether the token may authenticate (default true).
func (t Token) On() bool { return t.Enabled == nil || *t.Enabled }

// AuthConfig holds all accepted tokens.
type AuthConfig struct {
	Tokens []Token `yaml:"tokens"`
}

// Route maps a logical name to a local target address, or marks it as an
// stcp route whose two client sides are paired by the server.
type Route struct {
	Name string `yaml:"name"`
	// Type is RouteTypeTCP (default) or RouteTypeSTCP. A tcp route makes the
	// server dial Target; an stcp route has no target at all and instead
	// pairs a provider stream with a visitor stream.
	Type   string `yaml:"type,omitempty"`
	Target string `yaml:"target,omitempty"`
	// UseProxy sends this route's dials through the server-wide proxy when
	// one is enabled. Other routes keep dialing directly. Only meaningful
	// for tcp routes.
	UseProxy bool `yaml:"use_proxy,omitempty"`
	// Bind, for stcp routes only, makes the server listen on this address
	// (for example 127.0.0.1:1234 or 0.0.0.0:1234) and expose the route
	// directly: every accepted connection is paired with a provider client.
	Bind string `yaml:"bind,omitempty"`
}

// Route types.
const (
	// RouteTypeTCP is the classic behaviour: the server dials Target.
	RouteTypeTCP = "tcp"
	// RouteTypeSTCP pairs a provider client (whose local service is exposed)
	// with a visitor client through the server. No target is dialed.
	RouteTypeSTCP = "stcp"
)

// TunnelServer tunes server-side tunnel behaviour.
type TunnelServer struct {
	MaxConcurrentStreams int           `yaml:"max_concurrent_streams"`
	MaxConnections       int           `yaml:"max_connections"`
	DialTimeout          time.Duration `yaml:"dial_timeout"`
	IdleTimeout          time.Duration `yaml:"idle_timeout"`
	// XHTTPPath is the URL prefix for the xhttp transport endpoints.
	// Defaults to /relay; change it when another service already owns that
	// prefix on the same domain.
	XHTTPPath string `yaml:"xhttp_path"`
	// QuotaRefresh is how often token traffic limits are re-evaluated.
	// Defaults to 5m.
	QuotaRefresh time.Duration `yaml:"quota_refresh"`
	// STCPTimeout bounds how long a pending stcp stream waits for its peer
	// (a provider waits for a visitor and vice versa). Defaults to 30s.
	STCPTimeout time.Duration `yaml:"stcp_timeout"`
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

// DefaultListen is the tunnel listen address used when the config omits
// `listen`. It can be overridden with the server's -listen / -port flags.
const DefaultListen = ":5630"

// Validate checks the configuration, applies defaults and fills derived
// state.
func (c *ServerConfig) Validate() error {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if len(c.Auth.Tokens) == 0 {
		return fmt.Errorf("auth.tokens: at least one token required")
	}
	seen := map[string]bool{}
	for i := range c.Auth.Tokens {
		t := &c.Auth.Tokens[i]
		if t.Token == "" {
			return fmt.Errorf("auth.tokens: empty token value (name=%q)", t.Name)
		}
		if seen[t.Token] {
			return fmt.Errorf("auth.tokens: duplicate token (name=%q)", t.Name)
		}
		seen[t.Token] = true
		if t.DailyLimitMB < 0 || t.WeeklyLimitMB < 0 || t.MonthlyLimitMB < 0 {
			return fmt.Errorf("auth.tokens: traffic limits must not be negative (name=%q)", t.Name)
		}
	}
	if len(c.Routes) == 0 {
		return fmt.Errorf("routes: at least one route required")
	}
	c.routeTable = make(map[string]string, len(c.Routes))
	c.routeProxy = make(map[string]bool, len(c.Routes))
	c.routeType = make(map[string]string, len(c.Routes))
	seenRoutes := map[string]bool{}
	seenBinds := map[string]bool{}
	for i := range c.Routes {
		r := &c.Routes[i]
		if r.Name == "" {
			return fmt.Errorf("routes: name is required")
		}
		if seenRoutes[r.Name] {
			return fmt.Errorf("routes: duplicate name %q", r.Name)
		}
		seenRoutes[r.Name] = true
		rt := strings.ToLower(strings.TrimSpace(r.Type))
		switch rt {
		case "":
			rt = RouteTypeTCP
		case RouteTypeTCP, RouteTypeSTCP:
		default:
			return fmt.Errorf("routes: type for %q must be %s or %s, got %q",
				r.Name, RouteTypeTCP, RouteTypeSTCP, r.Type)
		}
		r.Type = rt
		c.routeType[r.Name] = rt
		c.routeProxy[r.Name] = r.UseProxy
		if rt == RouteTypeSTCP {
			if strings.TrimSpace(r.Target) != "" {
				return fmt.Errorf("routes: target must be empty for stcp route %q", r.Name)
			}
			if bind := strings.TrimSpace(r.Bind); bind != "" {
				if err := validateBind(bind); err != nil {
					return fmt.Errorf("routes: bind for %q: %w", r.Name, err)
				}
				if bind == c.Listen {
					return fmt.Errorf("routes: bind for %q must differ from listen", r.Name)
				}
				if seenBinds[bind] {
					return fmt.Errorf("routes: duplicate bind %q", bind)
				}
				seenBinds[bind] = true
				r.Bind = bind
			}
			continue
		}
		if r.Bind != "" {
			return fmt.Errorf("routes: bind is only supported for stcp routes (%q)", r.Name)
		}
		if r.Target == "" {
			return fmt.Errorf("routes: target is required for tcp route %q", r.Name)
		}
		addr, err := TargetAddress(r.Target)
		if err != nil {
			return fmt.Errorf("routes: target for %q: %w", r.Name, err)
		}
		c.routeTable[r.Name] = addr
	}
	if err := c.Proxy.Normalize(); err != nil {
		return fmt.Errorf("proxy: %w", err)
	}
	// Each route referenced by a token must exist.
	for _, t := range c.Auth.Tokens {
		for _, name := range t.Routes {
			if !seenRoutes[name] {
				return fmt.Errorf("auth.tokens: token %q references unknown route %q", t.Name, name)
			}
		}
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
	if c.Tunnel.QuotaRefresh <= 0 {
		c.Tunnel.QuotaRefresh = 5 * time.Minute
	}
	if c.Tunnel.STCPTimeout <= 0 {
		c.Tunnel.STCPTimeout = 30 * time.Second
	}
	xhttpPath, err := NormalizeXHTTPPath(c.Tunnel.XHTTPPath)
	if err != nil {
		return fmt.Errorf("tunnel.xhttp_path: %w", err)
	}
	c.Tunnel.XHTTPPath = xhttpPath
	if c.Log.Level == "" {
		c.Log.Level = "warn"
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log.level: must be debug, info, warn or error, got %q", c.Log.Level)
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

// validateBind checks a stcp route's exposed listen address: host:port with a
// port in 1-65535. An empty host means all interfaces.
func validateBind(addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("must be host:port: %w", err)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid port %q", port)
	}
	return nil
}

// BootstrapServer builds a minimal, valid configuration used when the server
// starts without a config file. The admin panel is enabled on the tunnel port
// (path /admin), the database defaults to data/admin.db, and a disabled
// placeholder Token plus a placeholder route keep the config valid until the
// operator edits them in the panel.
func BootstrapServer() (*ServerConfig, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("bootstrap token: %w", err)
	}
	off := false
	cfg := &ServerConfig{
		Listen: DefaultListen,
		Auth: AuthConfig{Tokens: []Token{{
			Name:    "bootstrap-placeholder",
			Token:   hex.EncodeToString(buf),
			Routes:  []string{"default"},
			Enabled: &off,
		}}},
		Routes: []Route{{Name: "default", Target: "127.0.0.1:22"}},
	}
	cfg.Admin.Enabled = true
	cfg.Admin.Shared = true
	cfg.Admin.Path = "/admin"
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// DefaultXHTTPPath is the default prefix for the xhttp transport endpoints.
const DefaultXHTTPPath = "/relay"

// NormalizeXHTTPPath validates and normalizes a path prefix such as /relay.
func NormalizeXHTTPPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return DefaultXHTTPPath, nil
	}
	if strings.ContainsAny(p, "?#") {
		return "", fmt.Errorf("must not contain a query or fragment, got %q", p)
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimRight(p, "/")
	if p == "" {
		return DefaultXHTTPPath, nil
	}
	return p, nil
}

// RouteTarget returns the local target for a route name. URL targets are
// normalized to a dialable host:port (https -> 443, http -> 80). stcp routes
// have no target and report ok=false; use RouteKind to distinguish them from
// unknown names.
func (c *ServerConfig) RouteTarget(name string) (string, bool) {
	t, ok := c.routeTable[name]
	return t, ok
}

// RouteKind returns the route type (RouteTypeTCP or RouteTypeSTCP). ok is
// false when the route is not configured.
func (c *ServerConfig) RouteKind(name string) (string, bool) {
	t, ok := c.routeType[name]
	return t, ok
}

// RouteIsSTCP reports whether name is a configured stcp route.
func (c *ServerConfig) RouteIsSTCP(name string) bool {
	return c.routeType[name] == RouteTypeSTCP
}

// TargetAddress turns a route target into a dialable host:port. Besides the
// classic "host:port" form it accepts http:// and https:// URLs so operators
// can paste an upstream URL; only scheme/host/port take part in the TCP
// dial, the path must be empty (or "/").
func TargetAddress(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("target is empty")
	}
	if !strings.Contains(target, "://") {
		if _, _, err := net.SplitHostPort(target); err != nil {
			return "", fmt.Errorf("must be host:port or http(s)://host[:port]: %w", err)
		}
		return target, nil
	}
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return "", fmt.Errorf("unsupported scheme %q (use http or https)", u.Scheme)
	}
	if u.User != nil {
		return "", fmt.Errorf("userinfo is not supported in route targets")
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("missing host")
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("path/query/fragment are not supported for TCP routes")
	}
	port := u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(u.Hostname(), port), nil
}

// RouteUsesProxy reports whether a route opted into the server-wide proxy.
func (c *ServerConfig) RouteUsesProxy(name string) bool {
	return c.routeProxy[name]
}
