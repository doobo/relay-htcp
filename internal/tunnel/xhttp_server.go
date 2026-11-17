package tunnel

import (
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

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
	done    chan struct{}
	once    sync.Once

	bytesIn  atomic.Int64 // upload -> target
	bytesOut atomic.Int64 // target -> download
	stat     *streamStat
}

func (ss *xhttpSession) send(f *protocol.Frame) error {
	ss.sendMu.Lock()
	defer ss.sendMu.Unlock()
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
// the response body open, forwarding target bytes as frames.
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
	dest, ok := cfg.RouteTarget(route)
	if !ok {
		http.Error(w, "unknown route", http.StatusNotFound)
		return
	}

	dialer := &net.Dialer{Timeout: cfg.Tunnel.DialTimeout}
	conn, err := dialer.DialContext(r.Context(), "tcp", dest)
	if err != nil {
		s.log.Warn("xhttp: dial target failed", "route", route, "dest", dest, "err", err)
		http.Error(w, "target unavailable", http.StatusBadGateway)
		return
	}

	fl, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if fl != nil {
		fl.Flush()
	}

	ss := &xhttpSession{
		id: id, token: entry.name, route: route, remote: r.RemoteAddr,
		conn: conn, w: w, fl: fl, done: make(chan struct{}),
	}
	if !s.addXHTTPSession(ss) {
		_ = conn.Close()
		s.log.Warn("xhttp: duplicate session", "session", id, "token", entry.name)
		return
	}
	ss.stat = s.registerStream(route, entry.name, r.RemoteAddr)
	// Flush any proxy/CDN response buffer before real data can be tiny.
	padding := make([]byte, xhttpPaddingBytes)
	_ = ss.send(&protocol.Frame{Type: protocol.TypeNoop, Payload: padding})
	defer func() {
		ss.close()
		s.removeXHTTPSession(id)
		s.finishStream(ss.stat, ss.bytesIn.Load(), ss.bytesOut.Load())
		s.log.Info("xhttp stream closed", "route", route, "token", entry.name,
			"session", id, "in", ss.bytesIn.Load(), "out", ss.bytesOut.Load())
	}()

	// target -> download
	go func() {
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
	rd := protocol.NewReader(r.Body)
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
}
