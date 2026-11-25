package speed

import (
	"bufio"
	"encoding/binary"
	"io"
	"math"
	"net"
	"testing"
	"time"
)

func TestMeterSkipsRampUp(t *testing.T) {
	m := &meter{start: time.Now()}
	// A 2-second burst of 10 MB in the first 0.5 s (buffers filling),
	// then a steady 1 MB per 100 ms = 80 Mbps.
	var b int64
	for i := 1; i <= 80; i++ {
		ts := time.Duration(i) * 100 * time.Millisecond
		if i <= 5 {
			b += 2_000_000
		} else {
			b += 1_000_000
		}
		m.samples = append(m.samples, point{ts, b})
	}
	mbps, bytes, dur := m.rate()
	if math.Abs(mbps-80) > 0.5 || bytes != b || dur != 8*time.Second {
		t.Errorf("rate = %.1f Mbps, %d bytes, %v; want 80 Mbps steady", mbps, bytes, dur)
	}
}

// serverFrame builds an unmasked server-to-client frame.
func serverFrame(op byte, p []byte) []byte {
	b := []byte{0x80 | op}
	switch n := len(p); {
	case n < 126:
		b = append(b, byte(n))
	case n <= 0xffff:
		b = append(b, 126, byte(n>>8), byte(n))
	default:
		b = append(b, 127)
		b = binary.BigEndian.AppendUint64(b, uint64(n))
	}
	return append(b, p...)
}

func TestWebSocketReadAndPong(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	w := &wsConn{c: client, br: bufio.NewReader(client)}

	go func() {
		_, _ = server.Write(serverFrame(opBinary, make([]byte, 70000))) // 64-bit length path
		_, _ = server.Write(serverFrame(opPing, []byte("hi")))
		// Read the client's pong before continuing (net.Pipe is synchronous).
		hdr := make([]byte, 2)
		_, _ = io.ReadFull(server, hdr)
		mask := make([]byte, 4)
		_, _ = io.ReadFull(server, mask)
		body := make([]byte, hdr[1]&0x7f)
		_, _ = io.ReadFull(server, body)
		for i := range body {
			body[i] ^= mask[i%4]
		}
		if hdr[0] != 0x80|opPong || hdr[1]&0x80 == 0 || string(body) != "hi" {
			t.Errorf("bad pong: hdr %x body %q", hdr, body)
		}
		_, _ = server.Write(serverFrame(opBinary, make([]byte, 300)))
		_, _ = server.Write(serverFrame(opText, []byte(`{"AppInfo":{"NumBytes":1}}`)))
		_, _ = server.Write(serverFrame(opClose, []byte{0x03, 0xe8}))
	}()

	var got int64
	text, err := w.read(func(n int64) { got += n })
	if err != nil || string(text) != `{"AppInfo":{"NumBytes":1}}` {
		t.Fatalf("text %q err %v", text, err)
	}
	if got != 70300 {
		t.Errorf("binary bytes = %d, want 70300", got)
	}
	if _, err := w.read(nil); err != io.EOF {
		t.Errorf("close frame: err = %v, want EOF", err)
	}
}

func TestClientFramesAreMasked(t *testing.T) {
	client, server := net.Pipe()
	w := &wsConn{c: client}
	payload := []byte("netdiag")
	go func() { _ = w.writeBinary(payload); client.Close() }()
	b, _ := io.ReadAll(server)
	if len(b) != 2+4+len(payload) || b[0] != 0x80|opBinary || b[1] != 0x80|byte(len(payload)) {
		t.Fatalf("frame header %x", b[:2])
	}
	for i := range payload {
		if b[6+i]^b[2+i%4] != payload[i] {
			t.Fatal("payload doesn't unmask to the original")
		}
	}
}
