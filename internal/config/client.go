package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Listener strategies decide which server a new local connection uses when a
// listener selects more than one server.
const (
	// StrategyRoundRobin rotates over the selected servers. If the chosen
	// server has no live tunnel, the next one is used.
	StrategyRoundRobin = "round_robin"
	// StrategyFailover always prefers the first selected server and only
	// moves to the next one when it has no live tunnel or a data stream
	// cannot be opened.
	StrategyFailover = "failover"
)

// Transport modes for reaching a server.
const (
	// TransportHTTP uses end-to-end HTTP/2 full-duplex POST streams. Fast,
	// but CDN/HTTP proxies usually buffer or reject them.
	TransportHTTP = "http"
	// TransportXHTTP splits every stream into short upload POSTs and one
	// long-lived download GET. This is the CDN/Cloudflare-friendly mode.
	TransportXHTTP = "xhttp"
)

// ClientConfig is the client side configuration.
type ClientConfig struct {
	// Server is the legacy single-server address. New configurations should
	// use Servers; when both are empty validation fails, and when only Server
	// is set it is migrated into Servers on load.
	Server    string           `yaml:"server,omitempty"`
	TLS       ClientTLS        `yaml:"tls"`
	Auth      ClientAuth       `yaml:"auth"`
	Servers   []ServerEndpoint `yaml:"servers"`
	Listeners []Listener       `yaml:"listeners"`
	Tunnel    TunnelClient     `yaml:"tunnel"`
	Disguise  ClientDisguise   `yaml:"disguise"`
	Log       LogConfig        `yaml:"log"`
	Admin     AdminConfig      `yaml:"admin"`
}

// ClientTLS tunes the client's TLS behaviour. It is the default for every
// server; each server entry may override ca_file / insecure_skip_verify.
type ClientTLS struct {
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	CAFile             string `yaml:"ca_file"`
}

// ClientAuth carries the default authentication token. Server entries may
// override it with their own token.
type ClientAuth struct {
	Token string `yaml:"token"`
}

// ServerEndpoint is one tunnel server the client can connect to.
type ServerEndpoint struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"` // e.g. https://tunnel.example.com:443
	// Token overrides auth.token for this server. Empty means "use the
	// global auth.token".
	Token string `yaml:"token"`
	// CAFile overrides tls.ca_file for this server.
	CAFile string `yaml:"ca_file"`
	// InsecureSkipVerify skips certificate checks for this server. It can
	// only enable skipping, not disable a globally enabled skip: the
	// effective value is tls.insecure_skip_verify || this flag.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
	// Transport is TransportHTTP (default) or TransportXHTTP.
	Transport string `yaml:"transport"`
	// XHTTPPath overrides the xhttp endpoint prefix. Defaults to /relay and
	// must match the server's tunnel.xhttp_path.
	XHTTPPath string `yaml:"xhttp_path"`
}

// ResolvedServer is a fully resolved server endpoint (defaults applied).
type ResolvedServer struct {
	Name      string
	URL       string
	Token     string
	TLS       ClientTLS
	Transport string
	XHTTPPath string
}

// Listener maps a local port to a server-side route.
type Listener struct {
	Local  string `yaml:"local"`
	Target string `yaml:"target"`
	// Servers selects which configured servers may carry this listener's
	// connections. Empty means all servers. Names refer to servers[].name.
	Servers []string `yaml:"servers"`
	// Strategy is StrategyRoundRobin (default) or StrategyFailover.
	Strategy string `yaml:"strategy"`
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

// Validate checks the configuration and applies defaults. The legacy top-level
// server field is migrated into Servers so the rest of the program only deals
// with one representation.
func (c *ClientConfig) Validate() error {
	if c.Server != "" && len(c.Servers) > 0 {
		return fmt.Errorf("server: cannot be combined with servers; use servers only")
	}
	if len(c.Servers) == 0 && c.Server != "" {
		c.Servers = []ServerEndpoint{{Name: "default", URL: c.Server}}
		c.Server = ""
	}
	// A client with the admin panel enabled may start empty: this is the
	// no-config bootstrap mode where the operator fills in servers and
	// listeners from the panel and then restarts.
	if len(c.Servers) == 0 && !c.Admin.Enabled {
		return fmt.Errorf("servers: at least one server required (enable admin for the bootstrap panel)")
	}
	serverNames := map[string]bool{}
	for i := range c.Servers {
		s := &c.Servers[i]
		if s.URL == "" {
			return fmt.Errorf("servers[%d].url: required", i)
		}
		if err := validateServerURL(s.URL); err != nil {
			return fmt.Errorf("servers[%d].url: %w", i, err)
		}
		if s.Name == "" {
			s.Name = fmt.Sprintf("server-%d", i+1)
		}
		if serverNames[s.Name] {
			return fmt.Errorf("servers: duplicate name %q", s.Name)
		}
		serverNames[s.Name] = true
		if s.Token == "" && c.Auth.Token == "" {
			return fmt.Errorf("servers[%d]: token required (set servers[].token or auth.token)", i)
		}
		switch s.Transport {
		case "", TransportHTTP:
			s.Transport = TransportHTTP
		case TransportXHTTP, "splithttp":
			s.Transport = TransportXHTTP
		default:
			return fmt.Errorf("servers[%d].transport: must be %s or %s, got %q",
				i, TransportHTTP, TransportXHTTP, s.Transport)
		}
		xhttpPath, err := NormalizeXHTTPPath(s.XHTTPPath)
		if err != nil {
			return fmt.Errorf("servers[%d].xhttp_path: %w", i, err)
		}
		s.XHTTPPath = xhttpPath
	}
	if len(c.Listeners) == 0 && !c.Admin.Enabled {
		return fmt.Errorf("listeners: at least one required")
	}
	seen := map[string]bool{}
	for i := range c.Listeners {
		l := &c.Listeners[i]
		if l.Local == "" || l.Target == "" {
			return fmt.Errorf("listeners[%d]: local and target are required", i)
		}
		if seen[l.Local] {
			return fmt.Errorf("listeners: duplicate local address %q", l.Local)
		}
		seen[l.Local] = true
		if l.Strategy == "" {
			l.Strategy = StrategyRoundRobin
		}
		switch l.Strategy {
		case StrategyRoundRobin, StrategyFailover:
		default:
			return fmt.Errorf("listeners[%d].strategy: must be %s or %s, got %q",
				i, StrategyRoundRobin, StrategyFailover, l.Strategy)
		}
		selected := map[string]bool{}
		for _, name := range l.Servers {
			if !serverNames[name] {
				return fmt.Errorf("listeners[%d].servers: unknown server %q", i, name)
			}
			if selected[name] {
				return fmt.Errorf("listeners[%d].servers: duplicate server %q", i, name)
			}
			selected[name] = true
		}
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
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log.level: must be debug, info, warn or error, got %q", c.Log.Level)
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

// BootstrapClient builds a minimal client used when no config file is found.
// It only opens the admin panel; servers and listeners are configured there.
func BootstrapClient() (*ClientConfig, error) {
	cfg := &ClientConfig{}
	cfg.Admin.Enabled = true
	cfg.Admin.Path = "/admin"
	cfg.Admin.Listen = "127.0.0.1:8081"
	cfg.Admin.DBPath = filepath.Join("data", "client-admin.db")
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func validateServerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("must be scheme://host[:port] without a path, got %q", raw)
	}
	return nil
}

// ResolvedServers returns every configured server with the global token and
// TLS defaults applied. It also tolerates an unvalidated legacy config that
// still only sets the top-level Server field.
func (c *ClientConfig) ResolvedServers() []ResolvedServer {
	servers := c.Servers
	if len(servers) == 0 && c.Server != "" {
		servers = []ServerEndpoint{{Name: "default", URL: c.Server}}
	}
	out := make([]ResolvedServer, 0, len(servers))
	for _, s := range servers {
		tlsCfg := c.TLS
		if s.CAFile != "" {
			tlsCfg.CAFile = s.CAFile
		}
		if s.InsecureSkipVerify {
			tlsCfg.InsecureSkipVerify = true
		}
		token := s.Token
		if token == "" {
			token = c.Auth.Token
		}
		name := s.Name
		if name == "" {
			name = fmt.Sprintf("server-%d", len(out)+1)
		}
		transport := s.Transport
		if transport == "" {
			transport = TransportHTTP
		}
		xhttpPath := s.XHTTPPath
		if xhttpPath == "" {
			xhttpPath = DefaultXHTTPPath
		}
		out = append(out, ResolvedServer{
			Name: name, URL: s.URL, Token: token, TLS: tlsCfg,
			Transport: transport, XHTTPPath: xhttpPath,
		})
	}
	return out
}
