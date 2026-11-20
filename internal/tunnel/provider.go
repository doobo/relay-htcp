package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"relay-htcp/internal/config"
	"relay-htcp/internal/disguise"
	"relay-htcp/internal/protocol"
)

// stcp provider side.
//
// A provider keeps Pool warm streams per selected server. Each stream is a
// normal data stream marked X-Tunnel-Role: provider; the server parks it in
// the route's pairing queue and answers it only when a visitor shows up. The
// local service is dialed when the server sends START, so idle warm streams
// never hold a connection to the target.

// providerStreamDialTimeout bounds dialing the local service after pairing.
const providerStreamDialTimeout = 10 * time.Second

// errSTCPIdleStream reports that the server expired an unpaired provider
// stream. It is a normal condition, not a failure.
var errSTCPIdleStream = errors.New("stcp provider stream expired")

// providerState tracks one configured provider entry.
type providerState struct {
	cfg    config.Provider
	cancel context.CancelFunc
}

// StartProvider starts the provider workers for one config entry. It returns
// an error when the same route/local is already running or no server matches.
func (p *Pool) StartProvider(ctx context.Context, pr config.Provider) error {
	if ctx == nil {
		ctx = context.Background()
	}
	servers := p.providerServers(pr.Servers)
	if len(servers) == 0 {
		return fmt.Errorf("stcp provider %s: no configured server selected", pr.Route)
	}
	key := pr.Key()
	pctx, cancel := context.WithCancel(ctx)
	p.pmu.Lock()
	if _, exists := p.providers[key]; exists {
		p.pmu.Unlock()
		cancel()
		return fmt.Errorf("stcp provider %s (%s) already running", pr.Route, pr.Local)
	}
	p.providers[key] = &providerState{cfg: pr, cancel: cancel}
	p.pmu.Unlock()

	for _, srv := range servers {
		for i := 0; i < pr.Pool; i++ {
			go p.providerWorker(pctx, srv, pr, i)
		}
	}
	p.log.Info("stcp provider started", "route", pr.Route, "local", pr.Local,
		"servers", providerServersLabel(pr.Servers), "pool", pr.Pool)
	return nil
}

// StopProvider stops one provider entry. Paired streams end when their request
// context is canceled.
func (p *Pool) StopProvider(key string) {
	p.pmu.Lock()
	st := p.providers[key]
	delete(p.providers, key)
	p.pmu.Unlock()
	if st != nil {
		st.cancel()
		p.log.Info("stcp provider stopped", "route", st.cfg.Route, "local", st.cfg.Local)
	}
}

// StopAllProviders stops every running provider entry.
func (p *Pool) StopAllProviders() {
	p.pmu.Lock()
	keys := make([]string, 0, len(p.providers))
	for key := range p.providers {
		keys = append(keys, key)
	}
	p.pmu.Unlock()
	for _, key := range keys {
		p.StopProvider(key)
	}
}

// StartProviders starts every configured provider that is not running yet.
func (p *Pool) StartProviders(ctx context.Context) error {
	for _, pr := range p.cfgGet().Providers {
		if p.providerActive(pr.Key()) {
			continue
		}
		if err := p.StartProvider(ctx, pr); err != nil {
			return err
		}
	}
	return nil
}

func (p *Pool) providerActive(key string) bool {
	p.pmu.Lock()
	defer p.pmu.Unlock()
	return p.providers[key] != nil
}

// providerServers resolves the provider's server selection. An empty list
// means every configured server, in configuration order.
func (p *Pool) providerServers(names []string) []*serverState {
	if len(names) == 0 {
		return p.servers
	}
	byName := make(map[string]*serverState, len(p.servers))
	for _, srv := range p.servers {
		byName[srv.name] = srv
	}
	out := make([]*serverState, 0, len(names))
	for _, name := range names {
		if srv := byName[name]; srv != nil {
			out = append(out, srv)
		}
	}
	return out
}

func providerServersLabel(names []string) string {
	if len(names) == 0 {
		return "all"
	}
	return strings.Join(names, ",")
}

// providerWorker keeps one warm provider stream open at a time: open, wait for
// pairing, serve, then immediately open a replacement.
func (p *Pool) providerWorker(ctx context.Context, srv *serverState, pr config.Provider, idx int) {
	cfg := p.cfgGet()
	minBackoff := cfg.Tunnel.ReconnectMin
	maxBackoff := cfg.Tunnel.ReconnectMax
	backoff := minBackoff
	for ctx.Err() == nil {
		t := p.waitTunnel(ctx, srv)
		if t == nil {
			return
		}
		err := p.runProviderStream(ctx, t, pr)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			backoff = minBackoff
			continue
		}
		p.log.Warn("stcp provider stream failed", "route", pr.Route, "local", pr.Local,
			"server", srv.name, "worker", idx, "err", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// waitTunnel blocks until the server has a live tunnel or ctx ends.
func (p *Pool) waitTunnel(ctx context.Context, srv *serverState) *tunnel {
	for ctx.Err() == nil {
		if t := srv.acquire(); t != nil && !t.closed() {
			return t
		}
		select {
		case <-ctx.Done():
			return nil
		case <-p.changes:
		case <-time.After(200 * time.Millisecond):
		}
	}
	return nil
}

// runProviderStream opens one provider stream and serves it until the server
// expires it or the paired session ends. A nil error means "reopen at once".
func (p *Pool) runProviderStream(ctx context.Context, t *tunnel, pr config.Provider) error {
	// Tie the stream to the tunnel: a reconnect aborts the old provider
	// stream instead of leaving it pinned to a dead HTTP connection.
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-t.dead:
			cancel()
		case <-sctx.Done():
		}
	}()

	if t.transport == config.TransportXHTTP {
		return p.runXHTTPProvider(sctx, t, pr)
	}
	return p.runHTTPProvider(sctx, t, pr)
}

func (p *Pool) runHTTPProvider(ctx context.Context, t *tunnel, pr config.Provider) error {
	prd, pwr := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url+DataPath, prd)
	if err != nil {
		_ = pwr.Close()
		return err
	}
	req.Header.Set("Authorization", "Bearer "+t.token)
	req.Header.Set("X-Tunnel-Target", pr.Route)
	req.Header.Set(TunnelRoleHeader, TunnelRoleProvider)
	req.Header.Set("X-Tunnel-Protocol", "relay-htcp/1")
	if cfg := p.cfgGet(); cfg.Disguise.On() {
		disguise.Apply(req, cfg.Disguise.UserAgent)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		_ = pwr.Close()
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		_ = pwr.Close()
		if resp.StatusCode == http.StatusNoContent {
			return nil // idle expiry: reopen immediately
		}
		return fmt.Errorf("server rejected stcp provider stream: %s %s", resp.Status, bytes.TrimSpace(body))
	}

	rd := protocol.NewReader(resp.Body)
	started, err := waitStreamStart(rd)
	if err != nil {
		_ = pwr.Close()
		if isStreamEnd(err) {
			return nil
		}
		return err
	}
	if !started {
		_ = pwr.Close()
		return nil
	}

	local, err := net.DialTimeout("tcp", pr.Local, providerStreamDialTimeout)
	if err != nil {
		_ = pwr.Close()
		return fmt.Errorf("dial provider local %s: %w", pr.Local, err)
	}
	defer local.Close()

	in, out, perr := pipeBidir(rd, pwr, local)
	_ = pwr.Close()
	p.log.Debug("stcp provider stream closed", "route", pr.Route, "server", t.server, "in", in, "out", out)
	if perr != nil && !isStreamEnd(perr) && !errors.Is(perr, net.ErrClosed) {
		p.log.Debug("stcp provider stream ended", "route", pr.Route, "err", perr)
	}
	return nil
}

func (p *Pool) runXHTTPProvider(ctx context.Context, t *tunnel, pr config.Provider) error {
	st, err := p.dialXHTTPStreamRole(ctx, t, pr.Route, TunnelRoleProvider)
	if err != nil {
		if errors.Is(err, errSTCPIdleStream) {
			return nil
		}
		return err
	}
	defer p.closeXHTTPStream(st)

	rd := protocol.NewReader(st.resp.Body)
	started, err := waitStreamStart(rd)
	if err != nil {
		if isStreamEnd(err) {
			return nil
		}
		return err
	}
	if !started {
		return nil
	}

	local, err := net.DialTimeout("tcp", pr.Local, providerStreamDialTimeout)
	if err != nil {
		return fmt.Errorf("dial provider local %s: %w", pr.Local, err)
	}
	defer local.Close()

	err = p.pumpXHTTPStream(ctx, st, rd, local, nil)
	if err != nil && !isStreamEnd(err) && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

// waitStreamStart consumes frames until the server says the stream is paired.
// PING/PONG/NOOP frames are ignored; CLOSE or EOF means it ended first.
func waitStreamStart(rd *protocol.Reader) (bool, error) {
	for {
		f, err := rd.Read()
		if err != nil {
			return false, err
		}
		switch f.Type {
		case protocol.TypeStart:
			return true, nil
		case protocol.TypeClose:
			return false, nil
		}
	}
}

// isStreamEnd reports the benign end-of-stream errors seen on normal closes.
func isStreamEnd(err error) bool {
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, context.Canceled)
}
