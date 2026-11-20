package tunnel

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"relay-htcp/internal/admin"
	"relay-htcp/internal/config"
	"relay-htcp/internal/disguise"
	"relay-htcp/internal/protocol"
)

// Tunnel request paths.
const (
	ControlPath = "/tunnel"
	DataPath    = "/stream"
	HealthPath  = "/health"

	// XHTTP transport: split upload/download so ordinary HTTP proxies and
	// CDNs (Cloudflare etc.) can carry the tunnel without full-duplex
	// HTTP/2 streaming. The prefix is configurable (tunnel.xhttp_path) and
	// defaults to /relay.
	XHTTPPingPath     = config.DefaultXHTTPPath + "/ping"
	XHTTPDownloadPath = config.DefaultXHTTPPath + "/download"
	XHTTPUploadPath   = config.DefaultXHTTPPath + "/upload"
)

// tokenEntry is one authenticated identity with its route permissions.
type tokenEntry struct {
	raw    string
	name   string
	routes map[string]bool // nil = all routes allowed
	// statsKey identifies this token in the daily traffic table. It is the
	// configured name, or a digest of the secret for unnamed tokens.
	statsKey     string
	limitEnabled bool
	dailyLimit   int64 // bytes, 0 = unlimited
	weeklyLimit  int64
	monthlyLimit int64
}

func (e *tokenEntry) allows(route string) bool {
	return e.routes == nil || e.routes[route]
}

// limitMB converts a configured MB value to bytes.
func limitMB(mb int64) int64 {
	if mb <= 0 {
		return 0
	}
	return mb * 1024 * 1024
}

// streamStat is one live data stream, kept for the admin status view.
type streamStat struct {
	id        int64
	route     string
	token     string
	tokenKey  string
	remote    string
	bytesIn   int64
	bytesOut  int64
	startedAt int64 // epoch ms
}

// controlStat is one live control stream.
type controlStat struct {
	name      string
	remote    string
	startedAt int64 // epoch ms
}

// stats holds live server counters for the admin panel.
type stats struct {
	mu       sync.Mutex
	streams  map[int64]*streamStat
	controls map[string]*controlStat
	bytesIn  atomic.Uint64 // tunnel -> target
	bytesOut atomic.Uint64 // target -> tunnel
}

// adminMount is the admin panel mounted on the tunnel listener.
type adminMount struct {
	prefix string
	h      http.Handler
}

// Server is the relay-htcp tunnel endpoint.
type Server struct {
	cfg    atomic.Pointer[config.ServerConfig]
	log    *slog.Logger
	tokens atomic.Pointer[[]tokenEntry]
	conns  atomic.Int64

	listenAddr string
	st         stats
	admin      atomic.Pointer[adminMount]
	// traffic is the shared admin recorder (nil when the panel is disabled).
	traffic atomic.Pointer[admin.TrafficStats]
	// blocked is the cached quota state per token stats key. The quota loop
	// refreshes it periodically; authenticate never queries the database.
	blocked  atomic.Pointer[map[string]bool]
	quotaRun sync.Once
	// rootToAdmin redirects "/" to the admin panel for clients allowed by
	// adminAllow. Other clients still get the decoy page.
	rootToAdmin atomic.Bool
	adminAllow  *admin.IPAllowlist
	// listenOverride, when set, pins the bound address for this run and wins
	// over both the file config and the saved database config.
	listenOverride string

	mu  sync.Mutex
	srv *http.Server
	// certs is the live TLS key pair when the listener serves TLS. It reloads
	// itself when the files change; ReloadTLS forces an immediate re-read.
	certs *certReloader

	// xhttp transport sessions, keyed by the client-generated session id.
	xmu       sync.Mutex
	xsessions map[string]*xhttpSession

	// stcp pairs provider and visitor streams on stcp routes.
	stcp *stcpHub
}

// NewServer builds a Server from a validated configuration.
func NewServer(cfg *config.ServerConfig, log *slog.Logger) *Server {
	tokens := buildTokens(cfg)
	s := &Server{log: log, xsessions: make(map[string]*xhttpSession), stcp: newSTCPHub()}
	s.cfg.Store(cfg)
	s.tokens.Store(&tokens)
	return s
}

func buildTokens(cfg *config.ServerConfig) []tokenEntry {
	tokens := make([]tokenEntry, 0, len(cfg.Auth.Tokens))
	for _, t := range cfg.Auth.Tokens {
		if !t.On() {
			continue
		}
		e := tokenEntry{
			raw: t.Token, name: t.Name,
			statsKey:     admin.TokenStatsKey(t.Token),
			limitEnabled: t.LimitEnabled,
			dailyLimit:   limitMB(t.DailyLimitMB),
			weeklyLimit:  limitMB(t.WeeklyLimitMB),
			monthlyLimit: limitMB(t.MonthlyLimitMB),
		}
		if len(t.Routes) > 0 {
			e.routes = make(map[string]bool, len(t.Routes))
			for _, r := range t.Routes {
				e.routes[r] = true
			}
		}
		tokens = append(tokens, e)
	}
	return tokens
}

// SetTraffic attaches the admin traffic recorder. Call it before Serve.
func (s *Server) SetTraffic(t *admin.TrafficStats) { s.traffic.Store(t) }

func (s *Server) trafficStats() *admin.TrafficStats { return s.traffic.Load() }

// TokenBlocked reports the cached quota state for a token stats key.
func (s *Server) TokenBlocked(statsKey string) bool {
	blocked := s.blocked.Load()
	if blocked == nil || statsKey == "" {
		return false
	}
	return (*blocked)[statsKey]
}

// tokenDenied reports whether a token is currently over its traffic limit.
func (s *Server) tokenDenied(entry *tokenEntry) bool {
	return entry != nil && s.TokenBlocked(entry.statsKey)
}

// cfgGet returns the currently effective configuration.
func (s *Server) cfgGet() *config.ServerConfig { return s.cfg.Load() }

// authenticate checks the Authorization header against the cached token list
// with constant-time comparison, keeping the timing uniform. The list and the
// quota blocked set are atomics refreshed on config apply / by the quota task,
// so authentication never queries the database.
func (s *Server) authenticate(r *http.Request) (*tokenEntry, bool) {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, prefix) {
		return nil, false
	}
	token := strings.TrimPrefix(auth, prefix)
	if token == "" {
		return nil, false
	}
	tokens := s.tokens.Load()
	var matched *tokenEntry
	for i := range *tokens {
		if subtle.ConstantTimeCompare([]byte(token), []byte((*tokens)[i].raw)) == 1 {
			matched = &(*tokens)[i]
		}
	}
	return matched, matched != nil
}

// registerControl records a live control stream for the admin view.
func (s *Server) registerControl(name, remote string) {
	cs := &controlStat{name: name, remote: remote, startedAt: time.Now().UnixMilli()}
	s.st.mu.Lock()
	if s.st.controls == nil {
		s.st.controls = make(map[string]*controlStat)
	}
	s.st.controls[remote] = cs
	s.st.mu.Unlock()
}

func (s *Server) unregisterControl(remote string) {
	s.st.mu.Lock()
	delete(s.st.controls, remote)
	s.st.mu.Unlock()
}

// registerStream records a live data stream for the admin view.
func (s *Server) registerStream(route string, entry *tokenEntry, remote string) *streamStat {
	ss := &streamStat{
		id:        time.Now().UnixNano(),
		route:     route,
		token:     entry.name,
		tokenKey:  entry.statsKey,
		remote:    remote,
		startedAt: time.Now().UnixMilli(),
	}
	s.st.mu.Lock()
	if s.st.streams == nil {
		s.st.streams = make(map[int64]*streamStat)
	}
	s.st.streams[ss.id] = ss
	s.st.mu.Unlock()
	return ss
}

func (s *Server) finishStream(ss *streamStat, in, out int64) {
	ss.bytesIn, ss.bytesOut = in, out
	s.st.bytesIn.Add(uint64(in))
	s.st.bytesOut.Add(uint64(out))
	if t := s.trafficStats(); t != nil && ss.tokenKey != "" {
		t.Record(admin.TrafficScopeServer, ss.tokenKey, "", ss.route, in, out)
	}
	s.st.mu.Lock()
	delete(s.st.streams, ss.id)
	s.st.mu.Unlock()
}

// MountAdmin serves h on the tunnel listener under prefix (for example
// "/admin"). It must be called before Serve/ServeListener.
func (s *Server) MountAdmin(prefix string, h http.Handler) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || prefix == "/" {
		s.admin.Store(&adminMount{prefix: "/", h: h})
		return
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	prefix = strings.TrimRight(prefix, "/")
	if prefix == "" {
		prefix = "/"
	}
	s.admin.Store(&adminMount{prefix: prefix, h: h})
}

// EnableAdminRootRedirect makes GET / redirect to the mounted panel for
// clients that pass the admin IP allowlist. Everyone else keeps seeing the
// decoy page, so the public root does not reveal the admin entry point.
func (s *Server) EnableAdminRootRedirect(allow *admin.IPAllowlist) {
	s.adminAllow = allow
	s.rootToAdmin.Store(true)
}

// ServeHTTP routes requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgGet()
	if cfg.Disguise.On() {
		w.Header().Set("Server", disguise.ImpersonatedServerHeader)
	}
	if m := s.admin.Load(); m != nil {
		if m.prefix == "/" || r.URL.Path == m.prefix || strings.HasPrefix(r.URL.Path, m.prefix+"/") {
			m.h.ServeHTTP(w, r)
			return
		}
		if s.rootToAdmin.Load() && r.URL.Path == "/" &&
			(s.adminAllow == nil || s.adminAllow.Allows(r.RemoteAddr)) {
			u := *r.URL
			u.Path = m.prefix + "/"
			http.Redirect(w, r, u.RequestURI(), http.StatusTemporaryRedirect)
			return
		}
	}
	xhttpBase := config.DefaultXHTTPPath
	if p, err := config.NormalizeXHTTPPath(cfg.Tunnel.XHTTPPath); err == nil {
		xhttpBase = p
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == xhttpBase+"/ping":
		s.handleXHTTPPing(w, r)
	case r.Method == http.MethodGet && r.URL.Path == xhttpBase+"/download":
		s.handleXHTTPDownload(w, r)
	case r.Method == http.MethodPost && r.URL.Path == xhttpBase+"/upload":
		s.handleXHTTPUpload(w, r)
	case r.Method == http.MethodPost && r.URL.Path == ControlPath:
		s.handleControl(w, r)
	case r.Method == http.MethodPost && r.URL.Path == DataPath:
		s.handleData(w, r)
	case r.Method == http.MethodGet && r.URL.Path == HealthPath:
		s.handleHealth(w, r)
	case cfg.Disguise.On():
		disguise.Decoy(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// enableFullDuplex lets an HTTP/1 handler interleave request body reads
// with response writes, which tunnel streams require (the request body has
// no end while the stream is alive). HTTP/2 already permits concurrent
// reads and responses natively, so it is a no-op there.
func enableFullDuplex(w http.ResponseWriter, r *http.Request) error {
	if r.ProtoMajor == 1 && r.ProtoMinor == 1 {
		return http.NewResponseController(w).EnableFullDuplex()
	}
	return nil
}

// handleControl serves the control stream: it authenticates, then loops on
// PING -> PONG frames, keeping the HTTP/2 connection (and NAT mappings)
// alive.
func (s *Server) handleControl(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgGet()
	entry, ok := s.authenticate(r)
	if !ok {
		s.log.Warn("control: unauthorized", "remote", r.RemoteAddr)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.tokenDenied(entry) {
		s.log.Warn("control: traffic quota exceeded", "token", entry.name, "remote", r.RemoteAddr)
		http.Error(w, "traffic quota exceeded", http.StatusTooManyRequests)
		return
	}
	n := s.conns.Add(1)
	if cfg.Tunnel.MaxConnections > 0 && n > int64(cfg.Tunnel.MaxConnections) {
		s.conns.Add(-1)
		http.Error(w, "too many connections", http.StatusServiceUnavailable)
		return
	}
	defer s.conns.Add(-1)

	if err := enableFullDuplex(w, r); err != nil {
		http.Error(w, "HTTP/2 required for tunnel streams", http.StatusUpgradeRequired)
		return
	}

	w.Header().Set("X-Tunnel-Protocol", "relay-htcp/1")
	w.WriteHeader(http.StatusOK)
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
	s.registerControl(entry.name, r.RemoteAddr)
	defer s.unregisterControl(r.RemoteAddr)

	// Idle watchdog: drop the control stream when it goes silent.
	var mu sync.Mutex
	lastSeen := time.Now()
	touch := func() {
		mu.Lock()
		lastSeen = time.Now()
		mu.Unlock()
	}
	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		idle := cfg.Tunnel.IdleTimeout
		ticker := time.NewTicker(idle / 3)
		defer ticker.Stop()
		for {
			select {
			case <-stopWatch:
				return
			case <-r.Context().Done():
				return
			case <-ticker.C:
				mu.Lock()
				silent := time.Since(lastSeen)
				mu.Unlock()
				if silent > idle {
					s.log.Warn("control stream idle timeout", "token", entry.name, "silent", silent.Round(time.Second))
					_ = r.Body.Close() // unblocks the read loop
					return
				}
			}
		}
	}()

	touch()
	rd := protocol.NewReader(r.Body)
	for {
		f, err := rd.Read()
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) &&
				!errors.Is(err, context.Canceled) {
				s.log.Debug("control stream read error", "token", entry.name, "err", err)
			}
			s.log.Debug("control stream closed", "token", entry.name)
			return
		}
		touch()
		switch f.Type {
		case protocol.TypePing:
			if werr := writeFrame(nil, w, &protocol.Frame{Type: protocol.TypePong, Payload: f.Payload}); werr != nil {
				s.log.Debug("control stream write failed", "token", entry.name, "err", werr)
				return
			}
		case protocol.TypeClose:
			return
		default:
			// DATA on the control stream: ignore.
		}
	}
}

// handleData serves one data stream: it authenticates, resolves the route,
// then either dials the target (tcp routes) or pairs it with the other side
// (stcp routes).
func (s *Server) handleData(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgGet()
	entry, ok := s.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.tokenDenied(entry) {
		http.Error(w, "traffic quota exceeded", http.StatusTooManyRequests)
		return
	}
	route := r.Header.Get("X-Tunnel-Target")
	if route == "" {
		http.Error(w, "missing X-Tunnel-Target", http.StatusBadRequest)
		return
	}
	if !entry.allows(route) {
		s.log.Warn("stream: route not permitted", "token", entry.name, "route", route, "remote", r.RemoteAddr)
		http.Error(w, "route not permitted", http.StatusForbidden)
		return
	}
	kind, ok := cfg.RouteKind(route)
	if !ok {
		http.Error(w, "unknown route", http.StatusNotFound)
		return
	}
	role, ok := stcpRole(r)
	if !ok {
		http.Error(w, "invalid "+TunnelRoleHeader, http.StatusBadRequest)
		return
	}
	if kind == config.RouteTypeSTCP {
		s.handleSTCPData(w, r, cfg, entry, route, role)
		return
	}
	if role == TunnelRoleProvider {
		http.Error(w, "route is not an stcp route", http.StatusBadRequest)
		return
	}

	dest, _ := cfg.RouteTarget(route)
	conn, err := s.dialRoute(r.Context(), cfg, route, dest)
	if err != nil {
		s.log.Warn("dial target failed", "route", route, "dest", dest, "proxy", cfg.Proxy.Enabled && cfg.RouteUsesProxy(route), "err", err)
		http.Error(w, "target unavailable", http.StatusBadGateway)
		return
	}

	if err := enableFullDuplex(w, r); err != nil {
		_ = conn.Close()
		http.Error(w, "HTTP/2 required for tunnel streams", http.StatusUpgradeRequired)
		return
	}

	w.WriteHeader(http.StatusOK)
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
	ss := s.registerStream(route, entry, r.RemoteAddr)

	in, out, perr := pipeBidir(protocol.NewReader(r.Body), w, conn)
	s.finishStream(ss, in, out)
	if perr != nil && !errors.Is(perr, io.EOF) && !errors.Is(perr, io.ErrUnexpectedEOF) &&
		!errors.Is(perr, context.Canceled) {
		s.log.Warn("data stream error", "route", route, "token", entry.name, "in", in, "out", out, "err", perr)
	} else {
		s.log.Info("data stream closed", "route", route, "token", entry.name, "in", in, "out", out)
	}
}

// stcpRole reads the stcp role from X-Tunnel-Role (or the role query
// parameter for transports that cannot set the header). An empty value means
// visitor, preserving compatibility with plain tcp-style streams.
func stcpRole(r *http.Request) (string, bool) {
	role := r.Header.Get(TunnelRoleHeader)
	if role == "" {
		role = r.URL.Query().Get("role")
	}
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "":
		return TunnelRoleVisitor, true
	case TunnelRoleVisitor:
		return TunnelRoleVisitor, true
	case TunnelRoleProvider:
		return TunnelRoleProvider, true
	default:
		return "", false
	}
}

// handleSTCPData pairs the stream with its counterpart on the same route and
// bridges the two. Pairing happens before the response headers are written, so
// an unmatched visitor still gets a clean 503 and an idle provider stream can
// be expired with 204. Once paired, the server sends the provider a START
// frame so it dials its local service only at that point.
func (s *Server) handleSTCPData(w http.ResponseWriter, r *http.Request, cfg *config.ServerConfig, entry *tokenEntry, route, role string) {
	timeout := cfg.Tunnel.STCPTimeout
	conn, err := s.stcp.pair(r.Context(), route, role, timeout)
	if err != nil {
		if role == TunnelRoleProvider {
			// A warm provider stream that never paired is not an error: the
			// client immediately opens a replacement.
			s.log.Debug("stcp provider stream ended without a visitor", "route", route, "token", entry.name, "err", err)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.log.Warn("stcp visitor found no provider", "route", route, "token", entry.name, "err", err)
		http.Error(w, "no stcp provider available", http.StatusServiceUnavailable)
		return
	}
	if err := enableFullDuplex(w, r); err != nil {
		_ = conn.Close()
		http.Error(w, "HTTP/2 required for tunnel streams", http.StatusUpgradeRequired)
		return
	}
	w.Header().Set("X-Tunnel-Protocol", "relay-htcp/1")
	w.WriteHeader(http.StatusOK)
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
	ss := s.registerStream(route, entry, r.RemoteAddr)
	if role == TunnelRoleProvider {
		if err := writeFrame(nil, w, &protocol.Frame{Type: protocol.TypeStart}); err != nil {
			_ = conn.Close()
			s.finishStream(ss, 0, 0)
			return
		}
	}
	in, out, perr := pipeBidir(protocol.NewReader(r.Body), w, conn)
	s.finishStream(ss, in, out)
	s.logSTCPEnd(role, route, entry, in, out, perr)
}

// logSTCPEnd reports a finished stcp stream without treating a normal hang-up
// as an error.
func (s *Server) logSTCPEnd(role, route string, entry *tokenEntry, in, out int64, err error) {
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) &&
		!errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, context.Canceled) &&
		!errors.Is(err, net.ErrClosed) {
		s.log.Warn("stcp stream error", "role", role, "route", route, "token", entry.name, "in", in, "out", out, "err", err)
		return
	}
	s.log.Info("stcp stream closed", "role", role, "route", route, "token", entry.name, "in", in, "out", out)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ok","connections":%d,"decoy_views":%d}`, s.conns.Load(), disguise.Views())
}

// SetListenOverride pins the listener address for this run. It takes
// precedence over the YAML file and any config restored from the admin
// database. Call it before Serve.
func (s *Server) SetListenOverride(addr string) {
	s.listenOverride = addr
}

// Serve listens on cfg.Listen (or the CLI override) and serves until ctx is
// canceled.
func (s *Server) Serve(ctx context.Context) error {
	addr := s.listenOverride
	if addr == "" {
		addr = s.cfgGet().Listen
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	return s.ServeListener(ctx, ln)
}

// ServeListener serves on an existing listener until ctx is canceled.
func (s *Server) ServeListener(ctx context.Context, ln net.Listener) error {
	cfg := s.cfgGet()
	s.listenAddr = ln.Addr().String()
	srv := &http.Server{
		Addr:    ln.Addr().String(),
		Handler: s,
		// Long-lived streaming handlers: no read/write deadlines here.
		IdleTimeout: 2 * time.Minute,
		ErrorLog:    slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams:          cfg.Tunnel.MaxConcurrentStreams,
			MaxReceiveBufferPerConnection: 1 << 20, // 1 MiB per connection
			MaxReceiveBufferPerStream:     1 << 20, // 1 MiB per stream
		},
	}
	if cfg.TLS.Enabled() {
		tlsCfg, err := s.buildTLSConfig()
		if err != nil {
			_ = ln.Close()
			return err
		}
		srv.TLSConfig = tlsCfg
	} else {
		// Cleartext mode: serve h2c alongside HTTP/1 so scanners see a
		// plain web server.
		protos := &http.Protocols{}
		protos.SetHTTP1(true)
		protos.SetUnencryptedHTTP2(true)
		srv.Protocols = protos
	}

	s.mu.Lock()
	s.srv = srv
	s.mu.Unlock()

	// Re-evaluate token traffic limits at startup and periodically.
	s.startQuotaLoop(ctx)

	errCh := make(chan error, 1)
	go func() {
		s.log.Info("relay-htcp server listening", "addr", ln.Addr().String(), "tls", cfg.TLS.Enabled())
		var err error
		if cfg.TLS.Enabled() {
			err = srv.ServeTLS(ln, "", "")
		} else {
			err = srv.Serve(ln)
		}
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := srv.Shutdown(shutCtx)
		cancel()
		if err != nil {
			s.log.Info("graceful shutdown timed out, forcing close")
			_ = s.Close()
		}
		return nil
	case err := <-errCh:
		return err
	}
}

// Close immediately stops the server and all active streams.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srv == nil {
		return nil
	}
	return s.srv.Close()
}

// buildTLSConfig loads the certificate and registers it with a reloader, so
// replacing the cert/key files (or sending SIGHUP) takes effect on the next
// handshake without dropping the listener.
func (s *Server) buildTLSConfig() (*tls.Config, error) {
	cfg := s.cfgGet()
	loader := newCertReloader(cfg.TLS.Cert, cfg.TLS.Key, s.log)
	if err := loader.load(); err != nil {
		return nil, fmt.Errorf("load certificate: %w", err)
	}
	s.mu.Lock()
	s.certs = loader
	s.mu.Unlock()
	return &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return loader.get()
		},
		MinVersion: tls.VersionTLS12,
		// Go does not inject "h2" into a user-supplied TLSConfig, so set
		// the ALPN protocols explicitly: h2 first, http/1.1 as fallback.
		NextProtos: []string{"h2", "http/1.1"},
	}, nil
}

// reloadCert re-reads the certificate and key for the live TLS listener. The
// listener itself is untouched: the next handshake gets the new certificate.
// Cleartext listeners have nothing to reload, and enabling or disabling TLS
// still requires a process restart (ApplyConfig reports that separately).
func (s *Server) reloadCert() error {
	s.mu.Lock()
	loader := s.certs
	s.mu.Unlock()
	if loader == nil {
		return nil
	}
	cfg := s.cfgGet()
	if !cfg.TLS.Enabled() {
		return nil
	}
	if err := loader.configure(cfg.TLS.Cert, cfg.TLS.Key); err != nil {
		return fmt.Errorf("reload certificate: %w", err)
	}
	return nil
}
