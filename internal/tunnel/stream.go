package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"relay-htcp/internal/disguise"
	"relay-htcp/internal/protocol"
)

// OpenStream forwards the local TCP connection through the tunnel to the
// named route. It blocks until the stream has ended in both directions.
// ac (optional) receives live byte counters for the admin status view.
func (p *Pool) OpenStream(ctx context.Context, t *tunnel, route string, local net.Conn, ac *activeConn) {
	cfg := p.cfgGet()
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Server+DataPath, pr)
	if err != nil {
		p.log.Error("build stream request failed", "route", route, "err", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Auth.Token)
	req.Header.Set("X-Tunnel-Target", route)
	if cfg.Disguise.On() {
		disguise.Apply(req, cfg.Disguise.UserAgent)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		p.log.Debug("stream open failed", "route", route, "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		p.log.Warn("server rejected stream", "route", route, "status", resp.Status, "body", strings.TrimSpace(string(body)))
		return
	}

	// local -> tunnel
	senderDone := make(chan struct{})
	var fwMu sync.Mutex
	go func() {
		defer close(senderDone)
		defer pw.Close()
		buf := make([]byte, protocol.MaxPayload)
		for {
			m, rerr := local.Read(buf)
			if m > 0 {
				if ac != nil {
					ac.bytesOut.Add(int64(m))
				}
				if werr := writeFrame(&fwMu, pw, &protocol.Frame{Type: protocol.TypeData, Payload: buf[:m]}); werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		_ = writeFrame(&fwMu, pw, &protocol.Frame{Type: protocol.TypeClose})
	}()

	// tunnel -> local; when this direction ends, close local so the sender
	// finishes, then wait for the request body to drain.
	in, perr := pumpFramesToConn(protocol.NewReader(resp.Body), local)
	if ac != nil {
		ac.bytesIn.Add(in)
	}
	local.Close()
	select {
	case <-senderDone:
	case <-ctx.Done():
		_ = pw.Close()
	}
	if perr != nil && !errors.Is(perr, io.EOF) && !errors.Is(perr, io.ErrUnexpectedEOF) {
		p.log.Debug("stream read ended", "route", route, "in", in, "err", perr)
	}
}
