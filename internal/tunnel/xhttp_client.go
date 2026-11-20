package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"relay-htcp/internal/config"
	"relay-htcp/internal/disguise"
	"relay-htcp/internal/protocol"
)

// XHTTP client side.
//
// Each logical stream (including the control plane) uses a short authenticated
// ping, one long-lived download GET and a sequence of short upload POSTs. This
// shape survives CDNs such as Cloudflare: no request body stays open and no
// response is required before the request body is consumed.

const (
	// xhttpSpareTTL bounds how long an unused pre-opened download stream may
	// hold a dialed target connection on the server.
	xhttpSpareTTL = 10 * time.Second
	// xhttpSparePerRoute is how many unused streams to keep per route/server.
	xhttpSparePerRoute = 1
	// xhttpPrewarmTimeout bounds the GET that fills the warm pool.
	xhttpPrewarmTimeout = 15 * time.Second
	// xhttpUploadInflight is how many upload POSTs may be in flight at once.
	// The server reorders them via the sequence header, so this hides one RTT
	// per batch on links with high latency.
	xhttpUploadInflight = 2
	// xhttpPipelineHeader is advertised by the server on the download
	// response; without it the client stays strictly sequential so it cannot
	// corrupt an older server that does not reorder uploads.
	xhttpPipelineHeader = "X-Upload-Pipeline"
	// xhttpUploadSeqHeader carries the 1-based batch sequence number.
	xhttpUploadSeqHeader = "X-Upload-Seq"
)

// xhttpStream is one opened download GET. Streams that were opened ahead of
// time and not claimed yet sit in Pool.spares.
type xhttpStream struct {
	sid      string
	tunnel   *tunnel
	route    string
	resp     *http.Response
	pipeline bool
	openedAt time.Time
	cancel   context.CancelFunc // non-nil for prewarmed streams
}

func xhttpSpareKey(server, route string) string { return server + "\x00" + route }

// openXHTTPStream opens the download GET, then pumps local -> upload POSTs and
// download frames -> local concurrently. A non-nil error means the stream was
// never opened, so the caller may fail over to another server.
func (p *Pool) openXHTTPStream(ctx context.Context, t *tunnel, route string, local net.Conn, ac *activeConn) error {
	st := p.takeSpareXHTTP(t, route)
	if st != nil {
		p.log.Debug("xhttp stream from warm pool", "route", route, "server", st.tunnel.server,
			"session", st.sid, "age", time.Since(st.openedAt).Round(time.Millisecond))
	} else {
		var err error
		st, err = p.dialXHTTPStream(ctx, t, route)
		if err != nil {
			return err
		}
	}
	// Keep one ready stream for the next local connection. This runs after a
	// stream has been used so idle routes never cause speculative dials.
	p.prewarmXHTTP(st.tunnel, route)
	return p.runXHTTPStream(ctx, st, local, ac)
}

// dialXHTTPStream opens one download GET and reports whether the server
// supports pipelined uploads.
func (p *Pool) dialXHTTPStream(ctx context.Context, t *tunnel, route string) (*xhttpStream, error) {
	return p.dialXHTTPStreamRole(ctx, t, route, "")
}

// dialXHTTPStreamRole is dialXHTTPStream with an explicit stcp role. An empty
// role opens a normal visitor stream.
func (p *Pool) dialXHTTPStreamRole(ctx context.Context, t *tunnel, route, role string) (*xhttpStream, error) {
	sid, err := newXHTTPSessionID()
	if err != nil {
		return nil, err
	}
	q := url.Values{"session": {sid}, "target": {route}}
	if role != "" {
		q.Set("role", role)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		t.xhttpURL("/download")+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	p.applyTunnelHeaders(req, t)
	req.Header.Set("X-Tunnel-Target", route)
	if role != "" {
		req.Header.Set(TunnelRoleHeader, role)
	}
	req.Header.Set("Cache-Control", "no-store")
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusNoContent {
			return nil, errSTCPIdleStream
		}
		return nil, fmt.Errorf("server rejected xhttp download: %s %s", resp.Status, bytes.TrimSpace(body))
	}
	return &xhttpStream{
		sid: sid, tunnel: t, route: route, resp: resp,
		pipeline: resp.Header.Get(xhttpPipelineHeader) == "1",
		openedAt: time.Now(),
	}, nil
}

func (p *Pool) closeXHTTPStream(st *xhttpStream) {
	if st == nil {
		return
	}
	_ = st.resp.Body.Close()
	if st.cancel != nil {
		st.cancel()
	}
}

// takeSpareXHTTP claims a pre-opened stream for this server and route.
func (p *Pool) takeSpareXHTTP(t *tunnel, route string) *xhttpStream {
	key := xhttpSpareKey(t.server, route)
	p.spareMu.Lock()
	list := p.spares[key]
	var picked *xhttpStream
	for len(list) > 0 {
		st := list[len(list)-1]
		list = list[:len(list)-1]
		if st.tunnel.closed() || time.Since(st.openedAt) > xhttpSpareTTL {
			p.closeXHTTPStream(st)
			continue
		}
		picked = st
		break
	}
	p.spares[key] = list
	p.spareMu.Unlock()
	return picked
}

// prewarmXHTTP opens one download GET in the background so the next local
// connection does not pay a full round trip before the first byte can flow.
func (p *Pool) prewarmXHTTP(t *tunnel, route string) {
	if t == nil || t.transport != config.TransportXHTTP {
		return
	}
	key := xhttpSpareKey(t.server, route)
	p.spareMu.Lock()
	if p.spareOpening[key] || len(p.spares[key]) >= xhttpSparePerRoute {
		p.spareMu.Unlock()
		return
	}
	p.spareOpening[key] = true
	p.spareMu.Unlock()

	base := p.runCtx
	if base == nil {
		base = context.Background()
	}
	go func() {
		ctx, cancel := context.WithCancel(base)
		timer := time.AfterFunc(xhttpPrewarmTimeout, cancel)
		st, err := p.dialXHTTPStream(ctx, t, route)
		if err != nil {
			timer.Stop()
			cancel()
			p.spareMu.Lock()
			delete(p.spareOpening, key)
			p.spareMu.Unlock()
			p.log.Debug("xhttp prewarm failed", "route", route, "server", t.server, "err", err)
			return
		}
		if !timer.Stop() {
			// The dial hit the timeout right after succeeding; discard it.
			p.closeXHTTPStream(st)
			cancel()
			p.spareMu.Lock()
			delete(p.spareOpening, key)
			p.spareMu.Unlock()
			return
		}
		st.cancel = cancel
		p.spareMu.Lock()
		delete(p.spareOpening, key)
		if t.closed() || len(p.spares[key]) >= xhttpSparePerRoute {
			p.spareMu.Unlock()
			p.closeXHTTPStream(st)
			return
		}
		p.spares[key] = append(p.spares[key], st)
		p.spareMu.Unlock()
		time.AfterFunc(xhttpSpareTTL, func() { p.expireSpareXHTTP(key, st) })
	}()
}

// expireSpareXHTTP drops a warm stream that was never claimed.
func (p *Pool) expireSpareXHTTP(key string, st *xhttpStream) {
	p.spareMu.Lock()
	list := p.spares[key]
	for i, s := range list {
		if s == st {
			p.spares[key] = append(list[:i], list[i+1:]...)
			break
		}
	}
	p.spareMu.Unlock()
	p.closeXHTTPStream(st)
}

// closeSparesXHTTP drops every warm stream, e.g. on client shutdown.
func (p *Pool) closeSparesXHTTP() {
	p.spareMu.Lock()
	all := p.spares
	p.spares = make(map[string][]*xhttpStream)
	p.spareMu.Unlock()
	for _, list := range all {
		for _, st := range list {
			p.closeXHTTPStream(st)
		}
	}
}

// runXHTTPStream binds an opened download stream to local and pumps both
// directions until either side ends.
func (p *Pool) runXHTTPStream(ctx context.Context, st *xhttpStream, local net.Conn, ac *activeConn) error {
	return p.pumpXHTTPStream(ctx, st, protocol.NewReader(st.resp.Body), local, ac)
}

// pumpXHTTPStream is runXHTTPStream with the frame reader already positioned.
// stcp providers read the START frame from it before calling this.
func (p *Pool) pumpXHTTPStream(ctx context.Context, st *xhttpStream, rd *protocol.Reader, local net.Conn, ac *activeConn) error {
	cfg := p.cfgGet()
	route := st.route
	t := st.tunnel
	sid := st.sid
	defer p.closeXHTTPStream(st)

	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	frames := make(chan *protocol.Frame, 64)
	uploadErr := make(chan error, 1)
	go p.xhttpUploadLoop(streamCtx, t, sid, frames, uploadErr, st.pipeline)
	go func() {
		select {
		case err := <-uploadErr:
			if err != nil {
				p.log.Debug("xhttp upload failed, closing stream",
					"route", route, "server", t.server, "err", err)
				cancel()
			}
		case <-streamCtx.Done():
		}
	}()
	p.log.Debug("xhttp stream opened", "route", route, "server", t.server, "session", sid,
		"pipeline", st.pipeline)

	stopKeepalive := make(chan struct{})
	defer close(stopKeepalive)
	go func() {
		ticker := time.NewTicker(cfg.Tunnel.Heartbeat)
		defer ticker.Stop()
		for {
			select {
			case <-streamCtx.Done():
				return
			case <-stopKeepalive:
				return
			case <-ticker.C:
				select {
				case frames <- &protocol.Frame{Type: protocol.TypePing}:
				case <-streamCtx.Done():
					return
				}
			}
		}
	}()

	go func() {
		buf := make([]byte, protocol.MaxPayload)
		for {
			n, rerr := local.Read(buf)
			if n > 0 {
				if ac != nil {
					ac.bytesOut.Add(int64(n))
				}
				payload := append([]byte(nil), buf[:n]...)
				select {
				case frames <- &protocol.Frame{Type: protocol.TypeData, Payload: payload}:
				case <-streamCtx.Done():
					return
				}
			}
			if rerr != nil {
				select {
				case frames <- &protocol.Frame{Type: protocol.TypeClose}:
				case <-streamCtx.Done():
				}
				return
			}
		}
	}()

	for {
		f, rerr := rd.Read()
		if rerr != nil {
			break
		}
		switch f.Type {
		case protocol.TypeData:
			if len(f.Payload) == 0 {
				continue
			}
			if ac != nil {
				ac.bytesIn.Add(int64(len(f.Payload)))
			}
			if _, werr := local.Write(f.Payload); werr != nil {
				cancel()
				_ = local.Close()
				return nil
			}
		case protocol.TypeClose:
			_ = local.Close()
			return nil
		case protocol.TypePing:
			select {
			case frames <- &protocol.Frame{Type: protocol.TypePong, Payload: f.Payload}:
			default:
			}
		}
	}
	_ = local.Close()
	return nil
}

// xhttpPing checks that the server is reachable and authenticated.
func (p *Pool) xhttpPing(ctx context.Context, t *tunnel) error {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, t.xhttpURL("/ping"), nil)
	if err != nil {
		return err
	}
	p.applyTunnelHeaders(req, t)
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("server rejected xhttp ping: %s", resp.Status)
	}
	return nil
}

// heartbeatXHTTP keeps the logical pool slot alive. A successful ping updates
// lastPong; HeartbeatMiss consecutive failures tear the slot down and trigger
// the normal reconnect loop.
func (p *Pool) heartbeatXHTTP(ctx context.Context, server string, idx int, t *tunnel) {
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
			if err := p.xhttpPing(ctx, t); err != nil {
				if ctx.Err() != nil {
					t.close()
					return
				}
				miss++
				p.log.Warn("xhttp ping failed", "server", server, "slot", idx,
					"missed", miss, "err", err)
				if miss >= cfg.Tunnel.HeartbeatMiss {
					p.log.Warn("xhttp heartbeat lost", "server", server, "slot", idx, "missed", miss)
					t.close()
					return
				}
				continue
			}
			miss = 0
			t.lastPong.Store(time.Now().UnixNano())
		}
	}
}

func (p *Pool) applyTunnelHeaders(req *http.Request, t *tunnel) {
	req.Header.Set("Authorization", "Bearer "+t.token)
	req.Header.Set("X-Tunnel-Protocol", "relay-htcp/1")
	cfg := p.cfgGet()
	if cfg.Disguise.On() {
		disguise.Apply(req, cfg.Disguise.UserAgent)
	}
}

// openXHTTPStream opens the download GET, then pumps local -> upload POSTs and
// xhttpURL joins the server base URL, the configured xhttp prefix and one of
// the /ping, /download or /upload suffixes.
func (t *tunnel) xhttpURL(suffix string) string {
	base := t.xhttpPath
	if base == "" {
		base = "/relay"
	}
	return t.url + base + suffix
}

// uploadBatch is one POST /relay/upload together with its 1-based sequence
// number, used by the server to apply pipelined batches in order.
type uploadBatch struct {
	seq    uint64
	frames []*protocol.Frame
}

// xhttpUploadLoop batches queued frames and sends them as upload POSTs. With
// pipelining (the server advertised X-Upload-Pipeline) several batches may be
// in flight at once, so a high-RTT link does not pay one round trip per batch;
// the server reorders them by sequence number.
func (p *Pool) xhttpUploadLoop(ctx context.Context, t *tunnel, sid string,
	frames <-chan *protocol.Frame, errCh chan<- error, pipeline bool) {

	workers := 1
	if pipeline {
		workers = xhttpUploadInflight
	}
	batches := make(chan uploadBatch, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for b := range batches {
				if err := p.xhttpUpload(ctx, t, sid, b); err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
			}
		}()
	}
	defer func() {
		close(batches)
		wg.Wait()
	}()

	var seq uint64
	for {
		var first *protocol.Frame
		select {
		case <-ctx.Done():
			return
		case first = <-frames:
		}
		batch := []*protocol.Frame{first}
	drain:
		for len(batch) < 32 {
			select {
			case f := <-frames:
				batch = append(batch, f)
			default:
				break drain
			}
		}
		seq++
		select {
		case batches <- uploadBatch{seq: seq, frames: batch}:
		case <-ctx.Done():
			return
		}
		for _, f := range batch {
			if f.Type == protocol.TypeClose {
				// Let the in-flight workers drain (defer waits for them), but
				// stop queueing PINGs against a session the server just closed.
				return
			}
		}
	}
}

func (p *Pool) xhttpUpload(ctx context.Context, t *tunnel, sid string, b uploadBatch) error {
	var buf bytes.Buffer
	for _, f := range b.frames {
		if err := f.Encode(&buf); err != nil {
			return err
		}
	}
	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	q := url.Values{"session": {sid}}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost,
		t.xhttpURL("/upload")+"?"+q.Encode(), bytes.NewReader(buf.Bytes()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(xhttpUploadSeqHeader, strconv.FormatUint(b.seq, 10))
	p.applyTunnelHeaders(req, t)
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("server rejected xhttp upload: %s %s", resp.Status, bytes.TrimSpace(body))
	}
	return nil
}

func newXHTTPSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
