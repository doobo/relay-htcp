// Package tunnel implements the relay-htcp tunnel server and client.
package tunnel

import (
	"errors"
	"io"
	"net"
	"sync"

	"relay-htcp/internal/protocol"
)

type flusher interface{ Flush() }

// writeFrame encodes f to w, holding mu (when non-nil) for the whole encode
// so concurrent writers cannot interleave headers and payloads.
func writeFrame(mu *sync.Mutex, w io.Writer, f *protocol.Frame) error {
	if mu != nil {
		mu.Lock()
		defer mu.Unlock()
	}
	if err := f.Encode(w); err != nil {
		return err
	}
	if fl, ok := w.(flusher); ok {
		fl.Flush()
	}
	return nil
}

// pumpFramesToConn consumes frames from fr and writes DATA payloads to conn
// until a CLOSE frame, stream end, or conn write error. It returns the
// number of bytes written to conn.
func pumpFramesToConn(fr *protocol.Reader, conn net.Conn) (int64, error) {
	var n int64
	for {
		f, err := fr.Read()
		if err != nil {
			return n, err
		}
		switch f.Type {
		case protocol.TypeData:
			if len(f.Payload) == 0 {
				continue
			}
			if _, werr := conn.Write(f.Payload); werr != nil {
				return n, werr
			}
			n += int64(len(f.Payload))
		case protocol.TypeClose:
			return n, nil
		default:
			// PING/PONG on a data stream: ignore.
		}
	}
}

// pumpConnToFrames reads conn and writes DATA frames to w until conn closes
// or w fails. It returns the number of bytes read from conn.
func pumpConnToFrames(conn net.Conn, w io.Writer, mu *sync.Mutex) (int64, error) {
	var n int64
	buf := make([]byte, protocol.MaxPayload)
	for {
		m, rerr := conn.Read(buf)
		if m > 0 {
			if werr := writeFrame(mu, w, &protocol.Frame{Type: protocol.TypeData, Payload: buf[:m]}); werr != nil {
				return n, werr
			}
			n += int64(m)
		}
		if rerr != nil {
			return n, rerr
		}
	}
}

// pipeBidir pumps frames and TCP bytes in both directions between the
// framer (fr in, fw out) and conn until either direction ends, then tears
// down: a final CLOSE frame is sent on fw (best effort) and conn is closed.
// It returns the bytes moved in each direction and the first meaningful
// error.
func pipeBidir(fr *protocol.Reader, fw io.Writer, conn net.Conn) (in, out int64, err error) {
	var mu sync.Mutex // guards all writes to fw

	type result struct {
		n   int64
		err error
	}
	resPeer := make(chan result, 1)
	resConn := make(chan result, 1)

	go func() {
		n, err := pumpFramesToConn(fr, conn)
		resPeer <- result{n, err}
	}()
	go func() {
		n, err := pumpConnToFrames(conn, fw, &mu)
		resConn <- result{n, err}
	}()

	var first result
	var firstFromPeer bool
	select {
	case first = <-resPeer:
		firstFromPeer = true
	case first = <-resConn:
	}

	// Either direction ended: tear down so the other one stops too.
	_ = writeFrame(&mu, fw, &protocol.Frame{Type: protocol.TypeClose})
	_ = conn.Close()

	var second result
	if firstFromPeer {
		second = <-resConn
	} else {
		second = <-resPeer
	}

	return first.n, second.n, pickError(first.err, second.err)
}

// pickError prefers a non-EOF error so callers log the real fault.
func pickError(a, b error) error {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if errors.Is(a, io.EOF) || errors.Is(a, io.ErrUnexpectedEOF) {
		return b
	}
	return a
}
