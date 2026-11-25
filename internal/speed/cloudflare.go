package speed

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/strlenstrlen/netdiag/internal/version"
)

// Cloudflare's public speed-test endpoints (the ones speed.cloudflare.com
// uses): GET __down?bytes=N returns N bytes; POST __up accepts a body.
// Several parallel connections, like a browser, so one TCP flow's limits
// don't understate the line.

const (
	cfDownChunk = 25_000_000
	cfUpChunk   = 10_000_000
)

func speedClient(timeout time.Duration) *http.Client {
	return &http.Client{Transport: &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: timeout}).DialContext,
		TLSHandshakeTimeout: timeout,
		MaxIdleConnsPerHost: 1, // one TCP connection per stream
	}}
}

// streams runs fn on n goroutines until ctx ends; returns the first error
// seen if no stream ever moved data.
func streams(ctx context.Context, n int, m *meter, fn func(ctx context.Context, c *http.Client) error) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var first error
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := speedClient(5 * time.Second)
			for ctx.Err() == nil {
				if err := fn(ctx, c); err != nil && ctx.Err() == nil {
					mu.Lock()
					if first == nil {
						first = err
					}
					mu.Unlock()
					return
				}
			}
		}()
	}
	wg.Wait()
	if m.total() > 0 {
		return nil
	}
	return first
}

func cloudflareDownload(ctx context.Context, url string, n int, m *meter, capBytes int64, stop context.CancelFunc) error {
	return streams(ctx, n, m, func(ctx context.Context, c *http.Client) error {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(url, cfDownChunk), nil)
		req.Header.Set("User-Agent", version.UserAgent())
		resp, err := c.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		buf := make([]byte, 64<<10)
		for {
			k, err := resp.Body.Read(buf)
			m.add(int64(k))
			if m.total() >= capBytes {
				stop()
			}
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
		}
	})
}

func cloudflareUpload(ctx context.Context, url string, n int, m *meter, capBytes int64, stop context.CancelFunc) error {
	block := make([]byte, 64<<10)
	_, _ = rand.Read(block) // incompressible, in case anything on the path compresses
	return streams(ctx, n, m, func(ctx context.Context, c *http.Client) error {
		body := &countingBody{remaining: cfUpChunk, block: block, m: m, capBytes: capBytes, stop: stop}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
		req.ContentLength = cfUpChunk
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("User-Agent", version.UserAgent())
		resp, err := c.Do(req)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return nil
	})
}

// countingBody feeds an upload and counts bytes as the transport takes them.
type countingBody struct {
	remaining int64
	block     []byte
	m         *meter
	capBytes  int64
	stop      context.CancelFunc
}

func (b *countingBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, io.EOF
	}
	k := copy(p, b.block[:min(int64(len(b.block)), b.remaining)])
	b.remaining -= int64(k)
	b.m.add(int64(k))
	if b.m.total() >= b.capBytes {
		b.stop()
	}
	return k, nil
}
