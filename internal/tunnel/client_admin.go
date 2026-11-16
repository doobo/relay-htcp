package tunnel

import (
	"fmt"
	"reflect"
	"time"

	"gopkg.in/yaml.v3"

	"relay-htcp/internal/admin"
	"relay-htcp/internal/config"
)

// admin.Provider implementation for the tunnel client.
//
// Hot-applied: local listeners (added, removed and retargeted live; in-flight
// connections on stopped listeners run to completion) and the disguise
// toggle (new streams pick it up).
//
// Restart-required: server address, auth token, TLS settings, every tunnel
// pool parameter (the pool is sized at startup) and the log level.

// Role implements admin.Provider.
func (p *Pool) Role() string { return "client" }

// Status implements admin.Provider.
func (p *Pool) Status() admin.Status {
	cfg := p.cfgGet()
	st := admin.Status{Role: "client", Client: &admin.ClientStatus{ServerAddr: cfg.Server}}
	for i, s := range p.slots {
		ss := admin.SlotStat{Index: i}
		if t := s.get(); t != nil {
			ss.State = slotStateName(t.state.Load())
			ss.ConnectedAt = t.connectedAt.Load()
			if !t.closed() {
				ss.LastPongAt = time.Unix(0, t.lastPong.Load()).UnixMilli()
			}
		} else {
			ss.State = admin.SlotStateReconnecting
		}
		st.Client.Slots = append(st.Client.Slots, ss)
	}
	p.lmu.Lock()
	for _, ls := range p.listeners {
		ls.mu.Lock()
		cons := make([]admin.ConnStat, 0, len(ls.active))
		for ac := range ls.active {
			cons = append(cons, admin.ConnStat{
				Local: ac.local, From: ac.from, Route: ac.route, StartedAt: ac.startedAt,
				BytesIn: ac.bytesIn.Load(), BytesOut: ac.bytesOut.Load(),
			})
		}
		ls.mu.Unlock()
		st.Client.Listeners = append(st.Client.Listeners, admin.ListenerStat{
			Local: ls.local, Target: ls.target, ActiveConns: len(cons),
		})
		st.Client.ActiveConns = append(st.Client.ActiveConns, cons...)
	}
	p.lmu.Unlock()
	return st
}

func slotStateName(v int32) admin.SlotState {
	switch v {
	case stateConnected:
		return admin.SlotStateConnected
	case stateReconnecting:
		return admin.SlotStateReconnecting
	default:
		return admin.SlotStateDialing
	}
}

// ValidateConfigYAML implements admin.Provider.
func (p *Pool) ValidateConfigYAML(y string) error {
	_, err := parseClientYAML(y)
	return err
}

func parseClientYAML(y string) (*config.ClientConfig, error) {
	var c config.ClientConfig
	if err := yaml.Unmarshal([]byte(y), &c); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// ApplyConfigYAML implements admin.Provider. Listeners are reconciled first
// (so a binding failure does not leave a half-applied config); the atomic
// config is swapped last.
func (p *Pool) ApplyConfigYAML(y string) (admin.SaveReport, error) {
	newCfg, err := parseClientYAML(y)
	if err != nil {
		return admin.SaveReport{}, err
	}
	old := p.cfgGet()
	// The admin section is file-managed runtime configuration, not part of
	// the editable tunnel config: keep the running value so panel saves
	// never clobber the panel's own settings (listen address, DB path).
	newCfg.Admin = old.Admin
	report := admin.SaveReport{}
	if old.Server != newCfg.Server {
		report.RestartRequired = append(report.RestartRequired, "server")
	}
	if old.Auth.Token != newCfg.Auth.Token {
		report.RestartRequired = append(report.RestartRequired, "auth.token")
	}
	if old.TLS != newCfg.TLS {
		report.RestartRequired = append(report.RestartRequired, "tls")
	}
	if old.Tunnel != newCfg.Tunnel {
		report.RestartRequired = append(report.RestartRequired, "tunnel")
	}
	if old.Log.Level != newCfg.Log.Level {
		report.RestartRequired = append(report.RestartRequired, "log.level")
	}

	// Reconcile listeners: stop removed ones, start new or retargeted ones.
	oldSet := make(map[string]config.Listener, len(old.Listeners))
	for _, l := range old.Listeners {
		oldSet[l.Local] = l
	}
	newSet := make(map[string]config.Listener, len(newCfg.Listeners))
	for _, l := range newCfg.Listeners {
		newSet[l.Local] = l
	}
	changed := false
	for _, l := range newCfg.Listeners {
		oldL, exists := oldSet[l.Local]
		if exists && oldL.Target == l.Target {
			continue
		}
		if exists {
			p.StopListener(l.Local)
		}
		if err := p.StartListener(p.runCtx, l); err != nil {
			return report, fmt.Errorf("start listener %s: %w", l.Local, err)
		}
		changed = true
	}
	for local := range oldSet {
		if _, ok := newSet[local]; !ok {
			p.StopListener(local)
			changed = true
		}
	}
	if changed {
		report.Applied = append(report.Applied, "listeners")
	}
	if !reflect.DeepEqual(old.Disguise, newCfg.Disguise) {
		report.Applied = append(report.Applied, "disguise")
	}

	p.cfg.Store(newCfg)
	return report, nil
}

// CurrentConfigYAML implements admin.Provider.
func (p *Pool) CurrentConfigYAML() string {
	b, err := yaml.Marshal(p.cfgGet())
	if err != nil {
		return ""
	}
	return string(b)
}

// ConfigFormSchema implements admin.Provider. Add a tunable here and it shows
// up in the panel's structured editor automatically.
func (p *Pool) ConfigFormSchema() admin.FormSchema {
	return admin.FormSchema{Sections: []admin.FormSection{
		{
			Title: "服务端连接",
			Fields: []admin.FormField{
				{Path: "server", Label: "服务端地址", Type: admin.FormText, Placeholder: "https://tunnel.example.com:443", Help: "格式 scheme://host[:port]，不能带路径；修改后需要重启"},
				{Path: "auth.token", Label: "认证 Token", Type: admin.FormSecret, Placeholder: "留空保持不变", Help: "必须与服务端一致；修改后需要重启"},
				{Path: "tls.ca_file", Label: "自定义 CA 文件", Type: admin.FormText, Placeholder: "server.crt", Help: "使用自签或私有 CA 时填写；修改后需要重启"},
				{Path: "tls.insecure_skip_verify", Label: "跳过证书校验（仅测试）", Type: admin.FormBool, Help: "修改后需要重启"},
			},
		},
		{
			Title: "本地监听",
			Fields: []admin.FormField{
				{Path: "listeners", Label: "监听列表", Type: admin.FormTable, Columns: []admin.FormField{
					{Path: "local", Label: "本地地址", Type: admin.FormText, Placeholder: "127.0.0.1:2222"},
					{Path: "target", Label: "服务端路由", Type: admin.FormText, Placeholder: "ssh"},
				}},
			},
		},
		{
			Title: "隧道参数",
			Fields: []admin.FormField{
				{Path: "tunnel.connections", Label: "连接池大小", Type: admin.FormNumber, Help: "需重启"},
				{Path: "tunnel.heartbeat", Label: "心跳间隔", Type: admin.FormDuration, Placeholder: "15s", Help: "需重启"},
				{Path: "tunnel.heartbeat_miss", Label: "心跳丢失上限", Type: admin.FormNumber, Help: "连续丢失多少次 PONG 判定断开；需重启"},
				{Path: "tunnel.reconnect_min", Label: "重连初始退避", Type: admin.FormDuration, Placeholder: "1s", Help: "需重启"},
				{Path: "tunnel.reconnect_max", Label: "重连最大退避", Type: admin.FormDuration, Placeholder: "30s", Help: "需重启"},
				{Path: "tunnel.stream_timeout", Label: "等待可用隧道超时", Type: admin.FormDuration, Placeholder: "30s", Help: "需重启"},
				{Path: "disguise.enabled", Label: "启用浏览器风格请求头", Type: admin.FormBool},
				{Path: "disguise.user_agent", Label: "自定义 User-Agent", Type: admin.FormText, Placeholder: "留空 = 内置 Chrome UA"},
				{Path: "log.level", Label: "日志级别", Type: admin.FormSelect, Options: []string{"debug", "info", "warn", "error"}, Help: "修改后需要重启"},
			},
		},
	}}
}
