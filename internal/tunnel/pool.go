package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	xproxy "golang.org/x/net/proxy"

	"relay-htcp/internal/config"
	"relay-htcp/internal/disguise"
	"relay-htcp/internal/protocol"
)

// tunnel lifecycle states.
const (
	stateDialing      = int32(0)
	stateConnected    = int32(1)
	stateReconnecting = int32(2)
)

// tunnel is one live tunnel connection: a control stream plus the data
// streams opened on demand over the same HTTP/2 connection. The endpoint
// fields pin every stream of this tunnel to the server it was dialed against.
type tunnel struct {
	client      *http.Client
	server      string // configured server name
	url         string // server base URL
	token       string // effective bearer token
	transport   string // config.TransportHTTP or config.TransportXHTTP
	xhttpPath   string // xhttp endpoint prefix (default /relay)
	pw          *io.PipeWriter
	resp        *http.Response
	dead        chan struct{}
	once        sync.Once
	lastPong    atomic.Int64 // unix nanos of the last PONG
	state       atomic.Int32 // one of stateDialing/Connected/Reconnecting
	connectedAt atomic.Int64 // epoch ms of the current connection
}

func (t *tunnel) close() {
	t.once.Do(func() {
		close(t.dead)
		if t.pw != nil {
			_ = t.pw.Close()
		}
		if t.resp != nil {
			_ = t.resp.Body.Close()
		}
	})
}

func (t *tunnel) closed() bool {
	select {
	case <-t.dead:
		return true
	default:
		return false
	}
}

// slot is one pool slot that keeps re-establishing its tunnel. Each slot has
// its own HTTP/2 transport so the pool spans N independent TCP/TLS
// connections.
type slot struct {
	client *http.Client
	mu     sync.RWMutex
	cur    *tunnel
}

func (s *slot) set(t *tunnel) {
	s.mu.Lock()
	s.cur = t
	s.mu.Unlock()
}

func (s *slot) get() *tunnel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur
}

// serverState is one configured tunnel server with its own pool of slots.
type serverState struct {
	name      string
	url       string
	token     string
	transport string
	xhttpPath string
	slots     []*slot
	next      atomic.Uint64
}

// acquire returns a live tunnel from this server, rotating over its slots.
func (s *serverState) acquire() *tunnel {
	n := len(s.slots)
	if n == 0 {
		return nil
	}
	start := int(s.next.Add(1) % uint64(n))
	for i := 0; i < n; i++ {
		if t := s.slots[(start+i)%n].get(); t != nil && !t.closed() {
			return t
		}
	}
	return nil
}

// online counts the currently usable slots.
func (s *serverState) online() int {
	n := 0
	for _, sl := range s.slots {
		if t := sl.get(); t != nil && !t.closed() {
			n++
		}
	}
	return n
}

// Pool maintains a pool of tunnel connections per configured server.
type Pool struct {
	cfg       atomic.Pointer[config.ClientConfig]
	log       *slog.Logger
	servers   []*serverState
	next      atomic.Uint64
	changes   chan struct{}
	startedAt time.Time
	runCtx    context.Context

	lmu       sync.Mutex
	listeners map[string]*listenerState

	// Warm pool of pre-opened xhttp download streams, keyed by
	// server+route; see prewarmXHTTP.
	spareMu      sync.Mutex
	spares       map[string][]*xhttpStream
	spareOpening map[string]bool
}

// NewPool builds the tunnel connection pools, one set of slots per server.
func NewPool(cfg *config.ClientConfig, log *slog.Logger) (*Pool, error) {
	p := &Pool{
		log:          log,
		changes:      make(chan struct{}, 1),
		listeners:    make(map[string]*listenerState),
		spares:       make(map[string][]*xhttpStream),
		spareOpening: make(map[string]bool),
		startedAt:    time.Now(),
	}
	p.cfg.Store(cfg)
	for _, rs := range cfg.ResolvedServers() {
		srv := &serverState{name: rs.Name, url: rs.URL, token: rs.Token,
			transport: rs.Transport, xhttpPath: rs.XHTTPPath}
		for i := 0; i < cfg.Tunnel.Connections; i++ {
			client, err := newSlotClient(rs.URL, rs.TLS, cfg.Proxy)
			if err != nil {
				return nil, fmt.Errorf("server %s: %w", rs.Name, err)
			}
			srv.slots = append(srv.slots, &slot{client: client})
		}
		p.servers = append(p.servers, srv)
	}
	// An empty pool is valid in bootstrap mode: the admin panel is open but
	// no server has been configured yet.
	return p, nil
}

// cfgGet returns the currently effective configuration.
func (p *Pool) cfgGet() *config.ClientConfig { return p.cfg.Load() }

// Start launches the keep-alive loop for every slot on every server.
func (p *Pool) Start(ctx context.Context) {
	p.runCtx = ctx
	for _, srv := range p.servers {
		for i, s := range srv.slots {
			go p.keepAlive(ctx, srv, i, s)
		}
	}
	go func() {
		<-ctx.Done()
		p.closeSparesXHTTP()
	}()
}

// Acquire returns a live tunnel for the listener, waiting up to timeout for
// one to become available.
func (p *Pool) Acquire(ctx context.Context, timeout time.Duration, l config.Listener) (*tunnel, error) {
	return p.acquire(ctx, timeout, l, nil)
}

// acquire is Acquire with an optional set of server names to skip (servers
// whose data stream already failed for this local connection).
func (p *Pool) acquire(ctx context.Context, timeout time.Duration, l config.Listener, exclude map[string]bool) (*tunnel, error) {
	servers := p.eligibleServers(l)
	if len(exclude) > 0 {
		filtered := make([]*serverState, 0, len(servers))
		for _, srv := range servers {
			if !exclude[srv.name] {
				filtered = append(filtered, srv)
			}
		}
		servers = filtered
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no eligible server left for listener %s", l.Local)
	}
	deadline := time.Now().Add(timeout)
	for {
		if t := p.pick(servers, l.Strategy); t != nil {
			return t, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("no live tunnel available (waited %s)", timeout)
		}
		wait := 200 * time.Millisecond
		if rem := time.Until(deadline); wait > rem {
			wait = rem
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-p.changes:
		case <-time.After(wait):
		}
	}
}

// eligibleServers resolves the listener's server selection. An empty list
// means every configured server, in configuration order.
func (p *Pool) eligibleServers(l config.Listener) []*serverState {
	if len(l.Servers) == 0 {
		return p.servers
	}
	byName := make(map[string]*serverState, len(p.servers))
	for _, srv := range p.servers {
		byName[srv.name] = srv
	}
	out := make([]*serverState, 0, len(l.Servers))
	for _, name := range l.Servers {
		if srv := byName[name]; srv != nil {
			out = append(out, srv)
		}
	}
	return out
}

// pick selects a live tunnel across the eligible servers according to the
// listener strategy.
func (p *Pool) pick(servers []*serverState, strategy string) *tunnel {
	if len(servers) == 0 {
		return nil
	}
	if strategy == config.StrategyFailover {
		for _, srv := range servers {
			if t := srv.acquire(); t != nil {
				return t
			}
		}
		return nil
	}
	start := int(p.next.Add(1) % uint64(len(servers)))
	for i := 0; i < len(servers); i++ {
		if t := servers[(start+i)%len(servers)].acquire(); t != nil {
			return t
		}
	}
	return nil
}

// activeConn tracks one local connection for the admin status view.
type activeConn struct {
	local     string
	from      string
	route     string
	server    string
	startedAt int64        // epoch ms
	bytesIn   atomic.Int64 // tunnel -> local
	bytesOut  atomic.Int64 // local -> tunnel
}

// listenerState tracks one bound local listener and its active connections.
type listenerState struct {
	local    string
	target   string
	servers  []string
	strategy string
	ln       net.Listener
	mu       sync.Mutex
	active   map[*activeConn]struct{}
}

func (ls *listenerState) track(c *activeConn) {
	ls.mu.Lock()
	ls.active[c] = struct{}{}
	ls.mu.Unlock()
}

func (ls *listenerState) untrack(c *activeConn) {
	ls.mu.Lock()
	delete(ls.active, c)
	ls.mu.Unlock()
}

// listenerFor returns the registered state for local, or nil.
func (p *Pool) listenerFor(local string) *listenerState {
	p.lmu.Lock()
	defer p.lmu.Unlock()
	return p.listeners[local]
}

func (p *Pool) listenerActive(local string) bool { return p.listenerFor(local) != nil }

// ServeListener accepts on ln until ctx is canceled or the listener is
// stopped. In-flight connections keep running on their own contexts.
func (p *Pool) ServeListener(ctx context.Context, ln net.Listener, l config.Listener) {
	p.log.Info("local listener started", "local", ln.Addr().String(), "route", l.Target,
		"servers", listenerServersLabel(l), "strategy", l.Strategy)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || (!p.listenerActive(l.Local) && errors.Is(err, net.ErrClosed)) {
				return
			}
			p.log.Warn("accept failed", "local", l.Local, "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go p.handleConn(ctx, conn, l)
	}
}

// StartListener binds and serves one local listener, registering it for the
// status view and hot-apply. The listener is stopped when ctx is canceled.
func (p *Pool) StartListener(ctx context.Context, l config.Listener) error {
	ln, err := net.Listen("tcp", l.Local)
	if err != nil {
		return fmt.Errorf("listen %s: %w", l.Local, err)
	}
	p.lmu.Lock()
	if _, exists := p.listeners[l.Local]; exists {
		p.lmu.Unlock()
		_ = ln.Close()
		return fmt.Errorf("listener %s already running", l.Local)
	}
	p.listeners[l.Local] = &listenerState{
		local:    l.Local,
		target:   l.Target,
		servers:  append([]string(nil), l.Servers...),
		strategy: l.Strategy,
		ln:       ln,
		active:   make(map[*activeConn]struct{}),
	}
	p.lmu.Unlock()
	go p.ServeListener(ctx, ln, l)
	go func() {
		<-ctx.Done()
		p.StopListener(l.Local)
	}()
	return nil
}

// StopListener stops a bound listener: no new connections; in-flight
// connections keep running to completion.
func (p *Pool) StopListener(local string) {
	p.lmu.Lock()
	ls := p.listeners[local]
	delete(p.listeners, local)
	p.lmu.Unlock()
	if ls != nil {
		_ = ls.ln.Close()
		p.log.Info("local listener stopped", "local", local, "route", ls.target)
	}
}

// StartListeners binds every configured local listener that is not running
// yet (idempotent). It returns the first binding error, rolling back only
// what this call started, and does not block.
func (p *Pool) StartListeners(ctx context.Context) error {
	started := []string{}
	for _, l := range p.cfgGet().Listeners {
		if p.listenerActive(l.Local) {
			continue
		}
		if err := p.StartListener(ctx, l); err != nil {
			for _, local := range started {
				p.StopListener(local)
			}
			return err
		}
		started = append(started, l.Local)
	}
	return nil
}

// StopAllListeners stops every bound listener.
func (p *Pool) StopAllListeners() {
	p.lmu.Lock()
	locals := make([]string, 0, len(p.listeners))
	for local := range p.listeners {
		locals = append(locals, local)
	}
	p.lmu.Unlock()
	for _, local := range locals {
		p.StopListener(local)
	}
}

func (p *Pool) handleConn(ctx context.Context, conn net.Conn, l config.Listener) {
	defer conn.Close()
	from := conn.RemoteAddr().String()
	ac := &activeConn{local: l.Local, from: from, route: l.Target, startedAt: time.Now().UnixMilli()}
	if ls := p.listenerFor(l.Local); ls != nil {
		ls.track(ac)
		defer ls.untrack(ac)
	}
	timeout := p.cfgGet().Tunnel.StreamTimeout
	tried := map[string]bool{}
	for {
		t, err := p.acquire(ctx, timeout, l, tried)
		if err != nil {
			p.log.Warn("no tunnel available, dropping connection", "from", from, "route", l.Target, "err", err)
			return
		}
		ac.server = t.server
		p.log.Debug("new local connection", "from", from, "route", l.Target, "server", t.server)
		start := time.Now()
		if err := p.OpenStream(ctx, t, l.Target, conn, ac); err == nil {
			p.log.Info("connection closed", "from", from, "route", l.Target, "server", t.server,
				"duration", time.Since(start).Round(time.Millisecond))
			return
		}
		// The stream could not be opened (no bytes from the local side have
		// been consumed yet), so fail over to the next eligible server.
		tried[t.server] = true
		p.log.Warn("data stream failed, trying next server", "from", from, "route", l.Target,
			"server", t.server, "tried", len(tried))
	}
}

// listenerServersLabel renders the listener's server selection for logs.
func listenerServersLabel(l config.Listener) string {
	if len(l.Servers) == 0 {
		return "all"
	}
	return strings.Join(l.Servers, ",")
}

// keepAlive (re)establishes a slot's tunnel forever: dial, run until dead,
// back off, repeat.
func (p *Pool) keepAlive(ctx context.Context, srv *serverState, idx int, s *slot) {
	cfg := p.cfgGet()
	backoff := cfg.Tunnel.ReconnectMin
	max := cfg.Tunnel.ReconnectMax
	for ctx.Err() == nil {
		t := &tunnel{
			client: s.client, server: srv.name, url: srv.url, token: srv.token,
			transport: srv.transport, xhttpPath: srv.xhttpPath, dead: make(chan struct{}),
		}
		t.state.Store(stateDialing)
		if err := p.dial(ctx, t); err != nil {
			if ctx.Err() != nil {
				return
			}
			p.log.Warn("tunnel dial failed", "server", srv.name, "slot", idx, "err", err, "retry_in", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > max {
				backoff = max
			}
			continue
		}
		backoff = cfg.Tunnel.ReconnectMin
		t.lastPong.Store(time.Now().UnixNano())
		t.state.Store(stateConnected)
		t.connectedAt.Store(time.Now().UnixMilli())
		s.set(t)
		p.signalChange()
		p.log.Info("tunnel established", "server", srv.name, "slot", idx, "url", srv.url)
		if t.transport == config.TransportXHTTP {
			go p.heartbeatXHTTP(ctx, srv.name, idx, t)
		} else {
			go p.readControl(ctx, srv.name, idx, t)
			go p.heartbeat(ctx, srv.name, idx, t)
		}
		<-t.dead
		t.state.Store(stateReconnecting)
		s.set(nil)
		p.signalChange()
		p.log.Info("tunnel closed, reconnecting", "server", srv.name, "slot", idx, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

func (p *Pool) signalChange() {
	select {
	case p.changes <- struct{}{}:
	default:
	}
}

// dial opens the control stream on the tunnel.
func (p *Pool) dial(ctx context.Context, t *tunnel) error {
	if t.transport == config.TransportXHTTP {
		return p.xhttpPing(ctx, t)
	}
	cfg := p.cfgGet()
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url+ControlPath, pr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+t.token)
	req.Header.Set("X-Tunnel-Protocol", "relay-htcp/1")
	if cfg.Disguise.On() {
		disguise.Apply(req, cfg.Disguise.UserAgent)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		_ = pw.Close()
		return err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		_ = pw.Close()
		return fmt.Errorf("server rejected tunnel: %s", resp.Status)
	}
	t.pw = pw
	t.resp = resp
	return nil
}

// readControl consumes the control stream response: PONGs update the
// liveness timestamp, CLOSE or stream end kills the tunnel.
func (p *Pool) readControl(ctx context.Context, server string, idx int, t *tunnel) {
	rd := protocol.NewReader(t.resp.Body)
	for {
		f, err := rd.Read()
		if err != nil {
			if !t.closed() {
				p.log.Info("control stream ended", "server", server, "slot", idx, "err", err)
			}
			t.close()
			return
		}
		switch f.Type {
		case protocol.TypePong:
			t.lastPong.Store(time.Now().UnixNano())
		case protocol.TypeClose:
			p.log.Info("server requested tunnel close", "server", server, "slot", idx)
			t.close()
			return
		}
	}
}

// heartbeat sends a PING every interval and kills the tunnel after
// HeartbeatMiss consecutive intervals without a PONG.
func (p *Pool) heartbeat(ctx context.Context, server string, idx int, t *tunnel) {
	cfg := p.cfgGet()
	iv := cfg.Tunnel.Heartbeat
	ticker := time.NewTicker(iv)
	defer ticker.Stop()
	miss := 0
	for {
		select {
		case <-ctx.Done():
			t.close()
			return
		case <-t.dead:
			return
		case <-ticker.C:
			last := time.Unix(0, t.lastPong.Load())
			if time.Since(last) > iv {
				miss++
			} else {
				miss = 0
			}
			if miss >= cfg.Tunnel.HeartbeatMiss {
				p.log.Warn("tunnel heartbeat lost", "server", server, "slot", idx, "missed", miss, "silent_for", time.Since(last).Round(time.Second))
				t.close()
				return
			}
			if err := writeFrame(nil, t.pw, &protocol.Frame{Type: protocol.TypePing}); err != nil {
				t.close()
				return
			}
		}
	}
}

// newSlotClient builds one HTTP/2-capable client for a server address. Each
// slot gets its own transport so a server's pool spans N independent
// TCP/TLS connections.
func newSlotClient(serverURL string, tlsCfgIn config.ClientTLS, proxyCfg config.ClientProxy) (*http.Client, error) {
	base := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 32, // xhttp keeps one long download GET per stream
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		HTTP2: &http.HTTP2Config{
			MaxReceiveBufferPerConnection: 1 << 20, // 1 MiB per connection
			MaxReceiveBufferPerStream:     1 << 20, // 1 MiB per stream
		},
	}
	if proxyCfg.Enabled {
		switch proxyCfg.Type {
		case config.ProxyHTTP:
			u := &url.URL{Scheme: "http", Host: proxyCfg.Address}
			if proxyCfg.Username != "" {
				u.User = url.UserPassword(proxyCfg.Username, proxyCfg.Password)
			}
			base.Proxy = http.ProxyURL(u)
		case config.ProxySOCKS5:
			var auth *xproxy.Auth
			if proxyCfg.Username != "" {
				auth = &xproxy.Auth{User: proxyCfg.Username, Password: proxyCfg.Password}
			}
			dialer, err := xproxy.SOCKS5("tcp", proxyCfg.Address, auth, xproxy.Direct)
			if err != nil {
				return nil, fmt.Errorf("socks5 proxy %s: %w", proxyCfg.Address, err)
			}
			base.Proxy = nil // a SOCKS5 dialer replaces the HTTP proxy path
			if cd, ok := dialer.(xproxy.ContextDialer); ok {
				base.DialContext = cd.DialContext
			} else {
				base.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.Dial(network, addr)
				}
			}
		}
	}
	if strings.HasPrefix(serverURL, "https://") {
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
			// Explicit ALPN: prefer h2, fall back to http/1.1.
			NextProtos: []string{"h2", "http/1.1"},
		}
		if tlsCfgIn.InsecureSkipVerify {
			tlsCfg.InsecureSkipVerify = true
		}
		if tlsCfgIn.CAFile != "" {
			pem, err := os.ReadFile(tlsCfgIn.CAFile)
			if err != nil {
				return nil, fmt.Errorf("read tls.ca_file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("tls.ca_file: no valid certificates found")
			}
			tlsCfg.RootCAs = pool
		}
		base.TLSClientConfig = tlsCfg
		// Supplying a custom TLSClientConfig makes http.Transport conservatively
		// disable HTTP/2 (golang/go#14275) unless we opt in explicitly; the
		// ALPN list above would otherwise advertise h2 while the client still
		// sends HTTP/1.1, desynchronizing both sides. Enable h2 (preferred)
		// with http/1.1 as fallback, mirroring the server's ALPN order.
		protos := &http.Protocols{}
		protos.SetHTTP1(true)
		protos.SetHTTP2(true)
		base.Protocols = protos
	} else {
		// h2c: cleartext HTTP/2 with prior knowledge for http:// URLs.
		protos := &http.Protocols{}
		protos.SetUnencryptedHTTP2(true)
		base.Protocols = protos
	}
	return &http.Client{Transport: base}, nil
}
