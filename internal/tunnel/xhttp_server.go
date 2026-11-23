package tunnel

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"

	"relay-htcp/internal/config"
	"relay-htcp/internal/protocol"
)

// XHTTP transport (CDN/Cloudflare friendly):
//
//	GET  /relay/download?session=<id>  long-lived response, server -> client
//	POST /relay/upload?session=<id>    short requests, client -> server
//	POST /relay/ping                   control-plane liveness
//
// The /relay prefix is configurable via tunnel.xhttp_path. Every stream has
// one download GET and a sequence of upload POSTs. Ordinary HTTP proxies can
// therefore forward it without full-duplex request bodies.

const maxXHTTPUploadBody = 4 << 20

// maxXHTTPUploadReorder bounds how many out-of-order upload batches a session
// may buffer while waiting for the missing sequence number.
const maxXHTTPUploadReorder = 8

// xhttpPaddingBytes is one NOOP padding frame at the start of every download.
// It nudges proxy/CDN response buffers that otherwise hold very small bodies.
const xhttpPaddingBytes = 512

type xhttpSession struct {
	id     string
	token  string
	route  string
	remote string
	conn   net.Conn
	w      http.ResponseWriter
	fl     http.Flusher

	sendMu  sync.Mutex // serializes writes to the download response
	writeMu sync.Mutex // serializes writes to the target connection

	// sendClosed is guarded by sendMu and set before the download handler
	// returns. A net/http ResponseWriter is only usable while its handler is
	// running: writing after it returns makes HTTP/2 panic with "Header called
	// after Handler finished" in whatever goroutine does the write. Holding
	// sendMu to set the flag also covers the case where a write is already in
	// flight, because the handler cannot return before that write finishes.
	sendClosed bool

	// Upload batches may arrive out of order once the client pipelines them:
	// upNext is the next sequence number to apply and upPending holds batches
	// that arrived early.
	upMu      sync.Mutex
	upNext    uint64
	upPending map[uint64][]*protocol.Frame

	done chan struct{}
	once sync.Once

	bytesIn  atomic.Int64 // upload -> target
	bytesOut atomic.Int64 // target -> download
	stat     *streamStat
}

func (ss *xhttpSession) send(f *protocol.Frame) error {
	ss.sendMu.Lock()
	defer ss.sendMu.Unlock()
	if ss.sendClosed {
		return net.ErrClosed
	}
	select {
	case <-ss.done:
		return net.ErrClosed
	default:
	}
	if err := f.Encode(ss.w); err != nil {
		return err
	}
	if ss.fl != nil {
		ss.fl.Flush()
	}
	return nil
}

// closeWriter permanently stops writes to the download response and waits for
// any in-flight write to finish. The download handler must call it before
// returning, otherwise the target->download goroutine can still be inside
// Encode/Flush when net/http recycles the ResponseWriter and panics.
func (ss *xhttpSession) closeWriter() {
	ss.sendMu.Lock()
	ss.sendClosed = true
	ss.sendMu.Unlock()
}

func (ss *xhttpSession) close() {
	ss.once.Do(func() {
		close(ss.done)
		_ = ss.conn.Close()
	})
}

func (ss *xhttpSession) closed() bool {
	select {
	case <-ss.done:
		return true
	default:
		return false
	}
}

func (s *Server) addXHTTPSession(ss *xhttpSession) bool {
	s.xmu.Lock()
	defer s.xmu.Unlock()
	if _, exists := s.xsessions[ss.id]; exists {
		return false
	}
	s.xsessions[ss.id] = ss
	return true
}

func (s *Server) getXHTTPSession(id string) *xhttpSession {
	s.xmu.Lock()
	defer s.xmu.Unlock()
	return s.xsessions[id]
}

func (s *Server) removeXHTTPSession(id string) {
	s.xmu.Lock()
	delete(s.xsessions, id)
	s.xmu.Unlock()
}

// handleXHTTPPing is a cheap authenticated request used by the client pool to
// mark a server as reachable. Short POSTs pass through CDNs unchanged.
func (s *Server) handleXHTTPPing(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authenticate(r); !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// handleXHTTPDownload opens the server -> client side of a stream and keeps
// the response body open, forwarding target bytes as frames. stcp routes pair
// with the opposite role instead of dialing a target.
func (s *Server) handleXHTTPDownload(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgGet()
	entry, ok := s.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := r.URL.Query().Get("session")
	if len(id) < 8 || len(id) > 128 {
		http.Error(w, "invalid session", http.StatusBadRequest)
		return
	}
	route := r.Header.Get("X-Tunnel-Target")
	if route == "" {
		route = r.URL.Query().Get("target")
	}
	if route == "" {
		http.Error(w, "missing X-Tunnel-Target", http.StatusBadRequest)
		return
	}
	if !entry.allows(route) {
		s.log.Warn("xhttp: route not permitted", "token", entry.name, "route", route, "remote", r.RemoteAddr)
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
		conn, err := s.stcp.pair(r.Context(), route, role, entry.statsKey, cfg.Tunnel.STCPTimeout)
		if err != nil {
			if role == TunnelRoleProvider {
				s.log.Debug("xhttp: stcp provider stream ended without a visitor", "route", route, "token", entry.name, "err", err)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			s.log.Warn("xhttp: stcp visitor found no provider", "route", route, "token", entry.name, "err", err)
			http.Error(w, "no stcp provider available", http.StatusServiceUnavailable)
			return
		}
		s.serveXHTTPDownload(w, r, entry, route, id, conn, role == TunnelRoleProvider)
		return
	}
	if role == TunnelRoleProvider {
		http.Error(w, "route is not an stcp route", http.StatusBadRequest)
		return
	}

	dest, _ := cfg.RouteTarget(route)
	conn, err := s.dialRoute(r.Context(), cfg, route, dest)
	if err != nil {
		s.log.Warn("xhttp: dial target failed", "route", route, "dest", dest, "proxy", cfg.Proxy.Enabled && cfg.RouteUsesProxy(route), "err", err)
		http.Error(w, "target unavailable", http.StatusBadGateway)
		return
	}
	s.serveXHTTPDownload(w, r, entry, route, id, conn, false)
}

// serveXHTTPDownload streams an established endpoint to the client as one
// long-lived download response. sendStart tells the stcp provider that its
// visitor is ready and it should dial its local service.
func (s *Server) serveXHTTPDownload(w http.ResponseWriter, r *http.Request, entry *tokenEntry, route, id string, conn net.Conn, sendStart bool) {
	fl, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	// Tell the client it may pipeline uploads; older clients ignore this and
	// keep sending strictly ordered batches without X-Upload-Seq.
	w.Header().Set(xhttpPipelineHeader, "1")
	w.WriteHeader(http.StatusOK)
	if fl != nil {
		fl.Flush()
	}

	ss := &xhttpSession{
		id: id, token: entry.name, route: route, remote: r.RemoteAddr,
		conn: conn, w: w, fl: fl, done: make(chan struct{}), upNext: 1,
	}
	if !s.addXHTTPSession(ss) {
		_ = conn.Close()
		s.log.Warn("xhttp: duplicate session", "session", id, "token", entry.name)
		return
	}
	ss.stat = s.registerStream(route, entry, r.RemoteAddr)
	// Flush any proxy/CDN response buffer before real data can be tiny.
	padding := make([]byte, xhttpPaddingBytes)
	_ = ss.send(&protocol.Frame{Type: protocol.TypeNoop, Payload: padding})
	// closeWriter first: it invalidates the ResponseWriter for every writer
	// (including upload-side PONGs) and waits for a write that is already in
	// flight, so nothing can touch w once this handler returns.
	defer func() {
		ss.closeWriter()
		ss.close()
		s.removeXHTTPSession(id)
		s.finishStream(ss.stat, ss.bytesIn.Load(), ss.bytesOut.Load())
		s.log.Info("xhttp stream closed", "route", route, "token", entry.name,
			"session", id, "in", ss.bytesIn.Load(), "out", ss.bytesOut.Load())
	}()
	if sendStart {
		if err := ss.send(&protocol.Frame{Type: protocol.TypeStart}); err != nil {
			return
		}
	}

	// target -> download
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		buf := make([]byte, protocol.MaxPayload)
		for {
			n, rerr := ss.conn.Read(buf)
			if n > 0 {
				ss.bytesOut.Add(int64(n))
				if serr := ss.send(&protocol.Frame{Type: protocol.TypeData, Payload: buf[:n]}); serr != nil {
					ss.close()
					return
				}
			}
			if rerr != nil {
				_ = ss.send(&protocol.Frame{Type: protocol.TypeClose})
				ss.close()
				return
			}
		}
	}()

	select {
	case <-ss.done:
	case <-r.Context().Done():
	}
	// Tear down in this order: stop the pump from writing to w, unblock its
	// conn.Read, then wait for it to exit. Waiting is what keeps the pump from
	// touching the ResponseWriter after this handler has finished.
	ss.closeWriter()
	ss.close()
	<-pumpDone
}

// handleXHTTPUpload consumes one short upload POST: frames are parsed and
// DATA payloads are written to the target. PING gets a PONG on the download
// stream, keeping CDN idle timers alive in both directions.
func (s *Server) handleXHTTPUpload(w http.ResponseWriter, r *http.Request) {
	entry, ok := s.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := r.URL.Query().Get("session")
	ss := s.getXHTTPSession(id)
	if ss == nil {
		http.Error(w, "unknown session", http.StatusNotFound)
		return
	}
	if ss.token != entry.name {
		http.Error(w, "session token mismatch", http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxXHTTPUploadBody)
	seq, hasSeq, ok := parseUploadSeq(r.Header.Get(xhttpUploadSeqHeader))
	if !ok {
		http.Error(w, "invalid upload seq", http.StatusBadRequest)
		return
	}
	rd := protocol.NewReader(r.Body)

	if !hasSeq {
		// Legacy sequential upload: apply frames as they arrive so a large
		// body streams straight into the target.
		for {
			f, err := rd.Read()
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					break
				}
				http.Error(w, "invalid frame", http.StatusBadRequest)
				return
			}
			switch f.Type {
			case protocol.TypeData:
				if len(f.Payload) == 0 {
					continue
				}
				ss.writeMu.Lock()
				_, werr := ss.conn.Write(f.Payload)
				ss.writeMu.Unlock()
				if werr != nil {
					s.log.Debug("xhttp: target write failed", "route", ss.route, "session", id, "err", werr)
					ss.close()
					http.Error(w, "stream closed", http.StatusGone)
					return
				}
				ss.bytesIn.Add(int64(len(f.Payload)))
			case protocol.TypePing:
				_ = ss.send(&protocol.Frame{Type: protocol.TypePong, Payload: f.Payload})
			case protocol.TypeClose:
				ss.close()
				w.WriteHeader(http.StatusOK)
				return
			}
		}
		if ss.closed() {
			http.Error(w, "stream closed", http.StatusGone)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	// Pipelined upload: buffer the batch, then apply everything that is now
	// contiguous from ss.upNext.
	var frames []*protocol.Frame
	for {
		f, err := rd.Read()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			http.Error(w, "invalid frame", http.StatusBadRequest)
			return
		}
		frames = append(frames, f)
	}
	if err := ss.applyUploadSeq(seq, frames); err != nil {
		s.log.Debug("xhttp: apply pipelined upload failed",
			"route", ss.route, "session", id, "seq", seq, "err", err)
		http.Error(w, "stream closed", http.StatusGone)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// parseUploadSeq reads the optional batch sequence header. present is false
// for legacy clients, ok is false for a malformed value.
func parseUploadSeq(v string) (seq uint64, present bool, ok bool) {
	if v == "" {
		return 0, false, true
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil || n == 0 {
		return 0, true, false
	}
	return n, true, true
}

// applyUploadSeq applies upload batches in order. Batches that arrive ahead of
// the missing sequence number are buffered until the gap is filled, which is
// what makes client-side upload pipelining safe.
func (ss *xhttpSession) applyUploadSeq(seq uint64, frames []*protocol.Frame) error {
	ss.upMu.Lock()
	defer ss.upMu.Unlock()
	if seq < ss.upNext {
		return nil // duplicate or retransmit: already applied
	}
	if seq > ss.upNext {
		if ss.upPending == nil {
			ss.upPending = make(map[uint64][]*protocol.Frame)
		}
		if _, dup := ss.upPending[seq]; dup {
			return nil
		}
		if len(ss.upPending) >= maxXHTTPUploadReorder {
			return fmt.Errorf("upload reorder buffer full (%d batches)", len(ss.upPending))
		}
		ss.upPending[seq] = frames
		return nil
	}
	if err := ss.applyUploadFrames(frames); err != nil {
		return err
	}
	ss.upNext++
	for {
		next, ok := ss.upPending[ss.upNext]
		if !ok {
			return nil
		}
		delete(ss.upPending, ss.upNext)
		if err := ss.applyUploadFrames(next); err != nil {
			return err
		}
		ss.upNext++
	}
}

// applyUploadFrames writes one in-order batch to the target connection.
func (ss *xhttpSession) applyUploadFrames(frames []*protocol.Frame) error {
	for _, f := range frames {
		switch f.Type {
		case protocol.TypeData:
			if len(f.Payload) == 0 {
				continue
			}
			ss.writeMu.Lock()
			_, werr := ss.conn.Write(f.Payload)
			ss.writeMu.Unlock()
			if werr != nil {
				ss.close()
				return werr
			}
			ss.bytesIn.Add(int64(len(f.Payload)))
		case protocol.TypePing:
			_ = ss.send(&protocol.Frame{Type: protocol.TypePong, Payload: f.Payload})
		case protocol.TypeClose:
			ss.close()
			return nil
		}
	}
	return nil
}
