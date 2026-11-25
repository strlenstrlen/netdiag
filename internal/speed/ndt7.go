package speed

// M-Lab NDT7 (https://github.com/m-lab/ndt-server/blob/main/spec/ndt7-protocol.md):
// ask the Locate API for a nearby server, then run a single-connection
// download or upload over a WebSocket with subprotocol net.measurementlab.ndt.v7.

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const ndt7Proto = "net.measurementlab.ndt.v7"

type ndt7Server struct {
	Machine  string
	City     string
	Country  string
	Download string
	Upload   string
}

func (s ndt7Server) label() string {
	if s.City != "" {
		return fmt.Sprintf("%s, %s", s.City, s.Country)
	}
	return s.Machine
}

func ndt7Locate(ctx context.Context, locateURL string, timeout time.Duration) ([]ndt7Server, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, locateURL, nil)
	req.Header.Set("User-Agent", userAgent)
	resp, err := speedClient(timeout).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("M-Lab locate: HTTP %d", resp.StatusCode)
	}
	var body struct {
		Results []struct {
			Machine  string `json:"machine"`
			Location struct {
				City    string `json:"city"`
				Country string `json:"country"`
			} `json:"location"`
			URLs map[string]string `json:"urls"`
		} `json:"results"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return nil, fmt.Errorf("M-Lab locate: %w", err)
	}
	var out []ndt7Server
	for _, r := range body.Results {
		s := ndt7Server{
			Machine: r.Machine, City: r.Location.City, Country: r.Location.Country,
			Download: r.URLs["wss:///ndt/v7/download"], Upload: r.URLs["wss:///ndt/v7/upload"],
		}
		if s.Download != "" && s.Upload != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("M-Lab locate: no servers returned")
	}
	return out, nil
}

// ndt7Measurement is the subset of the server's JSON messages we use.
type ndt7Measurement struct {
	AppInfo *struct {
		NumBytes    int64 `json:"NumBytes"`
		ElapsedTime int64 `json:"ElapsedTime"` // microseconds
	} `json:"AppInfo"`
	TCPInfo *struct {
		BytesReceived int64 `json:"BytesReceived"`
		ElapsedTime   int64 `json:"ElapsedTime"`
	} `json:"TCPInfo"`
}

func ndt7Download(ctx context.Context, u string, m *meter, capBytes int64, stop context.CancelFunc) error {
	w, err := wsDial(ctx, u, ndt7Proto, 5*time.Second)
	if err != nil {
		return err
	}
	defer w.Close()
	defer w.closeOnDone(ctx)()
	for {
		_, err := w.read(func(n int64) {
			m.add(n)
			if m.total() >= capBytes {
				stop()
			}
		})
		if err != nil {
			if err == io.EOF || ctx.Err() != nil {
				return nil // server finished, or we hit our time/data limit
			}
			return err
		}
	}
}

// ndt7Upload sends growing binary messages and returns the server's own
// count of bytes received per second (Mbps) when it reports one; that
// excludes data still sitting in local buffers.
func ndt7Upload(ctx context.Context, u string, m *meter, capBytes int64, stop context.CancelFunc) (serverMbps float64, err error) {
	w, err := wsDial(ctx, u, ndt7Proto, 5*time.Second)
	if err != nil {
		return 0, err
	}
	defer w.Close()
	defer w.closeOnDone(ctx)()

	var mu sync.Mutex
	var last ndt7Measurement
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			msg, err := w.read(nil)
			if err != nil {
				return
			}
			var x ndt7Measurement
			if json.Unmarshal(msg, &x) == nil && (x.AppInfo != nil || x.TCPInfo != nil) {
				mu.Lock()
				last = x
				mu.Unlock()
			}
		}
	}()

	// Message size starts at 8 KiB and doubles while it is under 1/16 of
	// the bytes sent so far, up to 16 MiB, as the spec recommends.
	size := 1 << 13
	payload := make([]byte, 1<<24)
	_, _ = rand.Read(payload)
	var sent int64
	for ctx.Err() == nil {
		if err := w.writeBinary(payload[:size]); err != nil {
			break
		}
		sent += int64(size)
		m.add(int64(size))
		if m.total() >= capBytes {
			stop()
		}
		if size < 1<<24 && int64(size) < sent/16 {
			size *= 2
		}
	}
	_ = w.c.SetDeadline(time.Now().Add(time.Second))
	<-readerDone

	mu.Lock()
	defer mu.Unlock()
	switch {
	case last.AppInfo != nil && last.AppInfo.ElapsedTime > 0:
		return float64(last.AppInfo.NumBytes) * 8 / float64(last.AppInfo.ElapsedTime), nil
	case last.TCPInfo != nil && last.TCPInfo.ElapsedTime > 0:
		return float64(last.TCPInfo.BytesReceived) * 8 / float64(last.TCPInfo.ElapsedTime), nil
	}
	if sent == 0 {
		return 0, errors.New("upload didn't start")
	}
	return 0, nil
}
