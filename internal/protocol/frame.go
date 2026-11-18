// Package protocol defines the relay-htcp binary frame protocol.
//
// All tunnel traffic — data streams and the control stream — is carried
// as frames:
//
//	+--------+---------------------+--------------------+
//	| type   | length (BE32)       | payload            |
//	| 1 byte | 4 bytes             | length bytes       |
//	+--------+---------------------+--------------------+
//
// Frame types:
//
//	0x0 DATA  carries a chunk of TCP payload
//	0x1 PING  heartbeat request (client -> server)
//	0x2 PONG  heartbeat response (server -> client, payload echoes the PING)
//	0x3 CLOSE graceful close request (payload is an optional reason)
//	0x4 NOOP  padding; ignored by receivers (flushes CDN response buffers)
package protocol

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Type identifies a frame kind.
type Type byte

const (
	TypeData  Type = 0x0
	TypePing  Type = 0x1
	TypePong  Type = 0x2
	TypeClose Type = 0x3
	// TypeNoop is padding. Receivers ignore it; it exists so CDN/proxy
	// response buffers are flushed early instead of holding small frames.
	TypeNoop Type = 0x4
)

const (
	// HeaderSize is the fixed frame header size.
	HeaderSize = 5
	// MaxPayload is the largest payload a single frame may carry. It keeps a
	// full frame close to the 16 KiB HTTP/2 DATA frame size.
	MaxPayload = 16383
)

// Protocol errors.
var (
	ErrInvalidType   = errors.New("protocol: invalid frame type")
	ErrPayloadTooBig = errors.New("protocol: frame payload too large")
)

// Frame is a single relay-htcp protocol frame.
type Frame struct {
	Type    Type
	Payload []byte
}

// String describes the frame without its payload.
func (f Frame) String() string {
	return fmt.Sprintf("frame{type=%s len=%d}", f.Type, len(f.Payload))
}

// String returns the type name.
func (t Type) String() string {
	switch t {
	case TypeData:
		return "DATA"
	case TypePing:
		return "PING"
	case TypePong:
		return "PONG"
	case TypeClose:
		return "CLOSE"
	case TypeNoop:
		return "NOOP"
	default:
		return fmt.Sprintf("0x%02x", byte(t))
	}
}

// Encode writes the frame to w.
//
// Header and payload go out in a single Write: every Write on an HTTP/2
// request body becomes its own DATA frame, and two writes per frame doubled
// the frame count (and small packets) for no benefit.
func (f *Frame) Encode(w io.Writer) error {
	if len(f.Payload) > MaxPayload {
		return ErrPayloadTooBig
	}
	buf := make([]byte, HeaderSize+len(f.Payload))
	buf[0] = byte(f.Type)
	binary.BigEndian.PutUint32(buf[1:], uint32(len(f.Payload)))
	copy(buf[HeaderSize:], f.Payload)
	_, err := w.Write(buf)
	return err
}

// Reader reads frames from a byte stream.
type Reader struct {
	r   *bufio.Reader
	buf [HeaderSize]byte
}

// NewReader wraps r for frame reading.
func NewReader(r io.Reader) *Reader {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReaderSize(r, 64*1024)
	}
	return &Reader{r: br}
}

// Read reads the next frame. io.EOF / io.ErrUnexpectedEOF are returned when
// the stream ends before a full frame is available; ErrInvalidType and
// ErrPayloadTooBig signal protocol violations.
func (rd *Reader) Read() (*Frame, error) {
	if _, err := io.ReadFull(rd.r, rd.buf[:]); err != nil {
		return nil, err
	}
	f := &Frame{Type: Type(rd.buf[0])}
	switch f.Type {
	case TypeData, TypePing, TypePong, TypeClose, TypeNoop:
	default:
		return nil, ErrInvalidType
	}
	n := int(binary.BigEndian.Uint32(rd.buf[1:]))
	if n > MaxPayload {
		return nil, ErrPayloadTooBig
	}
	if n > 0 {
		f.Payload = make([]byte, n)
		if _, err := io.ReadFull(rd.r, f.Payload); err != nil {
			return nil, err
		}
	}
	return f, nil
}
