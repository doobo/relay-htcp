package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"relay-htcp/internal/config"
	"relay-htcp/internal/disguise"
	"relay-htcp/internal/protocol"
)

// OpenStream forwards the local TCP connection through the tunnel to the
// named route. It blocks until the stream has ended in both directions.
// ac (optional) receives live byte counters for the admin status view.
//
// A non-nil error means the stream could not be opened at all; in that case
// no bytes have been read from local, so the caller may retry another server.
func (p *Pool) OpenStream(ctx context.Context, t *tunnel, route string, local net.Conn, ac *activeConn) error {
	if t.transport == config.TransportXHTTP {
		return p.openXHTTPStream(ctx, t, route, local, ac)
	}
	cfg := p.cfgGet()
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url+DataPath, pr)
	if err != nil {
		p.log.Error("build stream request failed", "route", route, "err", err)
		return err
	}
	req.Header.Set("Authorization", "Bearer "+t.token)
	req.Header.Set("X-Tunnel-Target", route)
	if cfg.Disguise.On() {
		disguise.Apply(req, cfg.Disguise.UserAgent)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		_ = pw.Close()
		p.log.Debug("stream open failed", "route", route, "server", t.server, "err", err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		_ = pw.Close()
		status := strings.TrimSpace(string(body))
		p.log.Warn("server rejected stream", "route", route, "server", t.server,
			"status", resp.Status, "body", status)
		return fmt.Errorf("server rejected stream: %s", resp.Status)
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
	return nil
}
