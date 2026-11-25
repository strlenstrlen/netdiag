package speed

// A minimal RFC 6455 WebSocket client: just enough for NDT7 (binary data,
// text measurements, ping/pong, close). Keeps netdiag dependency-free.

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/strlenstrlen/netdiag/internal/version"
)

const (
	opCont   = 0x0
	opText   = 0x1
	opBinary = 0x2
	opClose  = 0x8
	opPing   = 0x9
	opPong   = 0xA

	maxTextMessage = 1 << 20
)

type wsConn struct {
	c   net.Conn
	br  *bufio.Reader
	wmu sync.Mutex
	buf []byte // reused frame buffer for writes
}

func wsDial(ctx context.Context, rawURL, subprotocol string, timeout time.Duration) (*wsConn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "wss" {
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout}, Config: &tls.Config{ServerName: u.Hostname()}}
	c, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	keyBytes := make([]byte, 16)
	_, _ = rand.Read(keyBytes)
	key := base64.StdEncoding.EncodeToString(keyBytes)

	req := &http.Request{Method: http.MethodGet, URL: u, Host: u.Host, Header: http.Header{
		"Upgrade":                {"websocket"},
		"Connection":             {"Upgrade"},
		"Sec-Websocket-Key":      {key},
		"Sec-Websocket-Version":  {"13"},
		"Sec-Websocket-Protocol": {subprotocol},
		"User-Agent":             {version.UserAgent()},
	}}
	_ = c.SetDeadline(time.Now().Add(timeout))
	if err := req.Write(c); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReaderSize(c, 64<<10)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		c.Close()
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		c.Close()
		return nil, fmt.Errorf("websocket handshake: HTTP %d", resp.StatusCode)
	}
	h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if resp.Header.Get("Sec-Websocket-Accept") != base64.StdEncoding.EncodeToString(h[:]) {
		c.Close()
		return nil, errors.New("websocket handshake: bad accept key")
	}
	if !strings.EqualFold(resp.Header.Get("Sec-Websocket-Protocol"), subprotocol) {
		c.Close()
		return nil, errors.New("websocket handshake: server didn't accept " + subprotocol)
	}
	_ = c.SetDeadline(time.Time{})
	return &wsConn{c: c, br: br}, nil
}

// closeOnDone unblocks reads and writes when ctx ends.
func (w *wsConn) closeOnDone(ctx context.Context) (stop func() bool) {
	return context.AfterFunc(ctx, func() { _ = w.c.SetDeadline(time.Now()) })
}

func (w *wsConn) Close() error {
	w.wmu.Lock()
	_ = w.c.SetWriteDeadline(time.Now().Add(time.Second))
	_ = w.writeFrameLocked(opClose, []byte{0x03, 0xe8}) // 1000: normal closure
	w.wmu.Unlock()
	return w.c.Close()
}

// read returns the next text message. Binary payloads are discarded and
// their sizes reported to onData; pings are answered. Returns io.EOF when
// the server closes.
func (w *wsConn) read(onData func(int64)) ([]byte, error) {
	var text []byte
	inText := false
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(w.br, hdr[:]); err != nil {
			return nil, err
		}
		fin := hdr[0]&0x80 != 0
		op := hdr[0] & 0x0f
		masked := hdr[1]&0x80 != 0
		n := int64(hdr[1] & 0x7f)
		switch n {
		case 126:
			var b [2]byte
			if _, err := io.ReadFull(w.br, b[:]); err != nil {
				return nil, err
			}
			n = int64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			if _, err := io.ReadFull(w.br, b[:]); err != nil {
				return nil, err
			}
			n = int64(binary.BigEndian.Uint64(b[:]))
		}
		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(w.br, mask[:]); err != nil {
				return nil, err
			}
		}
		readPayload := func() ([]byte, error) {
			if n > maxTextMessage {
				return nil, errors.New("websocket message too large")
			}
			p := make([]byte, n)
			if _, err := io.ReadFull(w.br, p); err != nil {
				return nil, err
			}
			if masked {
				for i := range p {
					p[i] ^= mask[i%4]
				}
			}
			return p, nil
		}

		switch {
		case op == opText || (op == opCont && inText):
			p, err := readPayload()
			if err != nil {
				return nil, err
			}
			text = append(text, p...)
			inText = !fin
			if fin {
				return text, nil
			}
		case op == opBinary || op == opCont:
			if _, err := io.CopyN(counter(onData), w.br, n); err != nil {
				return nil, err
			}
		case op == opPing:
			p, err := readPayload()
			if err != nil {
				return nil, err
			}
			w.wmu.Lock()
			err = w.writeFrameLocked(opPong, p)
			w.wmu.Unlock()
			if err != nil {
				return nil, err
			}
		case op == opPong:
			if _, err := io.CopyN(io.Discard, w.br, n); err != nil {
				return nil, err
			}
		case op == opClose:
			_, _ = io.CopyN(io.Discard, w.br, n)
			return nil, io.EOF
		default:
			return nil, fmt.Errorf("websocket: unexpected opcode %#x", op)
		}
	}
}

func (w *wsConn) writeBinary(p []byte) error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	return w.writeFrameLocked(opBinary, p)
}

// writeFrameLocked writes one final, masked frame (clients must mask).
func (w *wsConn) writeFrameLocked(op byte, p []byte) error {
	n := len(p)
	need := 14 + n
	if cap(w.buf) < need {
		w.buf = make([]byte, need)
	}
	b := w.buf[:0]
	b = append(b, 0x80|op)
	switch {
	case n < 126:
		b = append(b, 0x80|byte(n))
	case n <= 0xffff:
		b = append(b, 0x80|126, byte(n>>8), byte(n))
	default:
		b = append(b, 0x80|127)
		b = binary.BigEndian.AppendUint64(b, uint64(n))
	}
	var mask [4]byte
	_, _ = rand.Read(mask[:])
	b = append(b, mask[:]...)
	off := len(b)
	b = append(b, p...)
	for i := range n {
		b[off+i] ^= mask[i%4]
	}
	_, err := w.c.Write(b)
	return err
}

type counter func(int64)

func (c counter) Write(p []byte) (int, error) {
	if c != nil {
		c(int64(len(p)))
	}
	return len(p), nil
}
