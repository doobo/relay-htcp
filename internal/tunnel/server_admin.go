package tunnel

import (
	"fmt"
	"reflect"

	"gopkg.in/yaml.v3"

	"relay-htcp/internal/admin"
	"relay-htcp/internal/config"
	"relay-htcp/internal/disguise"
)

// admin.Provider implementation for the tunnel server.
//
// Hot-applied: auth tokens, routes, dial/idle timeouts, max connections and
// the disguise toggle. These are read per request, so swapping the atomic
// config takes effect immediately.
//
// Restart-required: listen address, TLS certificate, max concurrent streams
// (baked into the http.Server) and the log level.

// Role implements admin.Provider.
func (s *Server) Role() string { return "server" }

// Status implements admin.Provider.
func (s *Server) Status() admin.Status {
	cfg := s.cfgGet()
	s.st.mu.Lock()
	streams := make([]admin.StreamStat, 0, len(s.st.streams))
	for _, ss := range s.st.streams {
		streams = append(streams, admin.StreamStat{
			ID: ss.id, Route: ss.route, Token: ss.token, Remote: ss.remote,
			BytesIn: ss.bytesIn, BytesOut: ss.bytesOut, StartedAt: ss.startedAt,
		})
	}
	controls := len(s.st.controls)
	s.st.mu.Unlock()
	return admin.Status{
		Role: "server",
		Server: &admin.ServerStatus{
			ListenAddr:    s.listenAddr,
			TLS:           cfg.TLS.Enabled(),
			ActiveTunnels: controls,
			ActiveStreams: streams,
			BytesIn:       s.st.bytesIn.Load(),
			BytesOut:      s.st.bytesOut.Load(),
			DecoyViews:    disguise.Views(),
		},
	}
}

// ValidateConfigYAML implements admin.Provider.
func (s *Server) ValidateConfigYAML(y string) error {
	_, err := parseServerYAML(y)
	return err
}

func parseServerYAML(y string) (*config.ServerConfig, error) {
	var c config.ServerConfig
	if err := yaml.Unmarshal([]byte(y), &c); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// ApplyConfigYAML implements admin.Provider. The config is swapped atomically
// after validation; the report distinguishes hot-applied fields from
// restart-required ones.
func (s *Server) ApplyConfigYAML(y string) (admin.SaveReport, error) {
	newCfg, err := parseServerYAML(y)
	if err != nil {
		return admin.SaveReport{}, err
	}
	old := s.cfgGet()
	// The admin section is file-managed runtime configuration, not part of
	// the editable tunnel config: keep the running value so panel saves
	// never clobber the panel's own settings (listen address, DB path).
	newCfg.Admin = old.Admin

	report := admin.SaveReport{}
	if old.Listen != newCfg.Listen {
		report.RestartRequired = append(report.RestartRequired, "listen")
	}
	if old.TLS != newCfg.TLS {
		report.RestartRequired = append(report.RestartRequired, "tls")
	}
	if old.Tunnel.MaxConcurrentStreams != newCfg.Tunnel.MaxConcurrentStreams {
		report.RestartRequired = append(report.RestartRequired, "tunnel.max_concurrent_streams")
	}
	if old.Log.Level != newCfg.Log.Level {
		report.RestartRequired = append(report.RestartRequired, "log.level")
	}

	tokens := buildTokens(newCfg)
	s.tokens.Store(&tokens)
	s.cfg.Store(newCfg)

	if !reflect.DeepEqual(old.Auth.Tokens, newCfg.Auth.Tokens) {
		report.Applied = append(report.Applied, "auth.tokens")
	}
	if !reflect.DeepEqual(old.Routes, newCfg.Routes) {
		report.Applied = append(report.Applied, "routes")
	}
	if old.Tunnel.DialTimeout != newCfg.Tunnel.DialTimeout ||
		old.Tunnel.IdleTimeout != newCfg.Tunnel.IdleTimeout ||
		old.Tunnel.MaxConnections != newCfg.Tunnel.MaxConnections {
		report.Applied = append(report.Applied, "tunnel.timeouts")
	}
	if old.Disguise.On() != newCfg.Disguise.On() {
		report.Applied = append(report.Applied, "disguise")
	}
	if old.Tunnel.XHTTPPath != newCfg.Tunnel.XHTTPPath {
		report.Applied = append(report.Applied, "tunnel.xhttp_path")
	}
	return report, nil
}

// CurrentConfigYAML implements admin.Provider.
func (s *Server) CurrentConfigYAML() string {
	b, err := yaml.Marshal(s.cfgGet())
	if err != nil {
		return ""
	}
	return string(b)
}

// ConfigFormSchema implements admin.Provider. Add a tunable here and it shows
// up in the panel's structured editor automatically.
func (s *Server) ConfigFormSchema() admin.FormSchema {
	return admin.FormSchema{Sections: []admin.FormSection{
		{
			Title: "监听与 TLS",
			Fields: []admin.FormField{
				{Path: "listen", Label: "隧道监听地址", Type: admin.FormText, Placeholder: ":8443", Help: "修改后需要重启"},
				{Path: "tls.cert", Label: "证书文件", Type: admin.FormText, Placeholder: "server.crt", Help: "与私钥同时留空时使用明文 h2c；修改后需要重启"},
				{Path: "tls.key", Label: "私钥文件", Type: admin.FormText, Placeholder: "server.key"},
				{Path: "log.level", Label: "日志级别", Type: admin.FormSelect, Options: []string{"debug", "info", "warn", "error"}, Help: "修改后需要重启"},
			},
		},
		{
			Title: "隧道参数",
			Fields: []admin.FormField{
				{Path: "tunnel.max_concurrent_streams", Label: "单连接并发流上限", Type: admin.FormNumber, Help: "修改后需要重启"},
				{Path: "tunnel.max_connections", Label: "在线控制连接上限", Type: admin.FormNumber, Help: "0 表示不限制"},
				{Path: "tunnel.dial_timeout", Label: "内网拨号超时", Type: admin.FormDuration, Placeholder: "10s"},
				{Path: "tunnel.idle_timeout", Label: "控制流空闲超时", Type: admin.FormDuration, Placeholder: "90s"},
				{Path: "tunnel.xhttp_path", Label: "xhttp 路径", Type: admin.FormText, Placeholder: "/relay", Help: "默认 /relay，需与客户端 servers[].xhttp_path 一致；避免与 Xray 等服务的 /xhttp 冲突"},
				{Path: "disguise.enabled", Label: "启用伪装（诱饵页与响应头）", Type: admin.FormBool},
			},
		},
		{
			Title: "内网路由",
			Fields: []admin.FormField{
				{Path: "routes", Label: "路由列表", Type: admin.FormTable, Columns: []admin.FormField{
					{Path: "name", Label: "路由名", Type: admin.FormText, Placeholder: "ssh"},
					{Path: "target", Label: "内网目标", Type: admin.FormText, Placeholder: "127.0.0.1:22"},
				}},
			},
		},
	}}
}
