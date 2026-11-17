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
	"time"

	"relay-htcp/internal/disguise"
	"relay-htcp/internal/protocol"
)

// XHTTP client side.
//
// Each logical stream (including the control plane) uses a short authenticated
// ping, one long-lived download GET and a sequence of short upload POSTs. This
// shape survives CDNs such as Cloudflare: no request body stays open and no
// response is required before the request body is consumed.

// xhttpURL joins the server base URL, the configured xhttp prefix and one of
// the /ping, /download or /upload suffixes.
func (t *tunnel) xhttpURL(suffix string) string {
	base := t.xhttpPath
	if base == "" {
		base = "/relay"
	}
	return t.url + base + suffix
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
// download frames -> local concurrently. A non-nil error means the stream was
// never opened, so the caller may fail over to another server.
func (p *Pool) openXHTTPStream(ctx context.Context, t *tunnel, route string, local net.Conn, ac *activeConn) error {
	cfg := p.cfgGet()
	sid, err := newXHTTPSessionID()
	if err != nil {
		return err
	}
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	q := url.Values{"session": {sid}, "target": {route}}
	req, err := http.NewRequestWithContext(streamCtx, http.MethodGet,
		t.xhttpURL("/download")+"?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	p.applyTunnelHeaders(req, t)
	req.Header.Set("X-Tunnel-Target", route)
	req.Header.Set("Cache-Control", "no-store")
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("server rejected xhttp download: %s %s", resp.Status, bytes.TrimSpace(body))
	}

	frames := make(chan *protocol.Frame, 64)
	uploadErr := make(chan error, 1)
	go p.xhttpUploadLoop(streamCtx, t, sid, frames, uploadErr)
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
	p.log.Debug("xhttp stream opened", "route", route, "server", t.server, "session", sid)

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

	rd := protocol.NewReader(resp.Body)
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

func (p *Pool) xhttpUploadLoop(ctx context.Context, t *tunnel, sid string,
	frames <-chan *protocol.Frame, errCh chan<- error) {
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
		if err := p.xhttpUpload(ctx, t, sid, batch); err != nil {
			select {
			case errCh <- err:
			default:
			}
			return
		}
		for _, f := range batch {
			if f.Type == protocol.TypeClose {
				return
			}
		}
	}
}

func (p *Pool) xhttpUpload(ctx context.Context, t *tunnel, sid string, frames []*protocol.Frame) error {
	var buf bytes.Buffer
	for _, f := range frames {
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
