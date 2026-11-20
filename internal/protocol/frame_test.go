package protocol

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	cases := []Frame{
		{Type: TypeData, Payload: []byte("hello")},
		{Type: TypePing, Payload: []byte{0x00, 0x00, 0x00, 0x01}},
		{Type: TypePong},
		{Type: TypeClose, Payload: []byte("bye")},
		{Type: TypeStart},
	}
	var buf bytes.Buffer
	for i := range cases {
		if err := cases[i].Encode(&buf); err != nil {
			t.Fatalf("encode frame %d: %v", i, err)
		}
	}
	rd := NewReader(&buf)
	for i, want := range cases {
		got, err := rd.Read()
		if err != nil {
			t.Fatalf("read frame %d: %v", i, err)
		}
		if got.Type != want.Type || !bytes.Equal(got.Payload, want.Payload) {
			t.Fatalf("frame %d = %+v, want %+v", i, got, want)
		}
	}
	if _, err := rd.Read(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF after all frames, got %v", err)
	}
}

func TestMaxPayloadFrame(t *testing.T) {
	payload := make([]byte, MaxPayload)
	for i := range payload {
		payload[i] = byte(i)
	}
	var buf bytes.Buffer
	if err := (&Frame{Type: TypeData, Payload: payload}).Encode(&buf); err != nil {
		t.Fatal(err)
	}
	got, err := NewReader(&buf).Read()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Fatal("payload mismatch")
	}
}

func TestEncodeRejectsOversized(t *testing.T) {
	f := &Frame{Type: TypeData, Payload: make([]byte, MaxPayload+1)}
	if err := f.Encode(io.Discard); !errors.Is(err, ErrPayloadTooBig) {
		t.Fatalf("got %v, want ErrPayloadTooBig", err)
	}
}

func TestInvalidType(t *testing.T) {
	buf := []byte{0xFF, 0, 0, 0, 0}
	if _, err := NewReader(bytes.NewReader(buf)).Read(); !errors.Is(err, ErrInvalidType) {
		t.Fatalf("got %v, want ErrInvalidType", err)
	}
}

func TestPayloadTooBig(t *testing.T) {
	buf := []byte{byte(TypeData), 0xFF, 0xFF, 0xFF, 0xFF}
	if _, err := NewReader(bytes.NewReader(buf)).Read(); !errors.Is(err, ErrPayloadTooBig) {
		t.Fatalf("got %v, want ErrPayloadTooBig", err)
	}
}

func TestHeaderEOF(t *testing.T) {
	// Truncated header: fewer bytes than HeaderSize.
	if _, err := NewReader(bytes.NewReader([]byte{byte(TypeData), 0, 0})).Read(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v, want ErrUnexpectedEOF", err)
	}
}

func TestPayloadEOF(t *testing.T) {
	// Header declares 10 bytes, only 3 follow.
	buf := []byte{byte(TypeData), 0, 0, 0, 10, 1, 2, 3}
	if _, err := NewReader(bytes.NewReader(buf)).Read(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v, want ErrUnexpectedEOF", err)
	}
}
