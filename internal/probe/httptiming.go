package probe

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"

	"github.com/strlenstrlen/netdiag/internal/version"
)

// HTTPTiming breaks one fresh HTTPS request into phases, answering "where
// does the time go before a page starts loading?".
type HTTPTiming struct {
	URL       string  `json:"url"`
	OK        bool    `json:"ok"`
	Status    int     `json:"status,omitempty"`
	DNSMs     float64 `json:"dns_ms"`     // name lookup (0 for IP literals or cache hits)
	ConnectMs float64 `json:"connect_ms"` // TCP handshake, about one round trip
	TLSMs     float64 `json:"tls_ms"`     // TLS handshake, one or two round trips
	ServerMs  float64 `json:"server_ms"`  // request sent → first byte: one round trip plus server time
	TotalMs   float64 `json:"total_ms"`   // start → first byte
	// Connection details, for single-site checks.
	RemoteAddr      string `json:"remote_addr,omitempty"`
	Location        string `json:"redirect,omitempty"`
	TLSVersion      string `json:"tls_version,omitempty"`
	CertIssuer      string `json:"cert_issuer,omitempty"`
	CertExpiresDays int    `json:"cert_expires_days,omitempty"`
	ErrKind         string `json:"error_kind,omitempty"`
	Err             string `json:"error,omitempty"`
}

func HTTPTime(ctx context.Context, rawURL string, timeout time.Duration) HTTPTiming {
	t := HTTPTiming{URL: rawURL}
	var dnsStart, dnsDone, connStart, connDone, tlsStart, tlsDone, wrote, firstByte time.Time
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:  func(httptrace.DNSDoneInfo) { dnsDone = time.Now() },
		ConnectStart: func(_, _ string) {
			if connStart.IsZero() {
				connStart = time.Now()
			}
		},
		ConnectDone: func(_, addr string, err error) {
			if err == nil && connDone.IsZero() {
				connDone = time.Now()
				t.RemoteAddr = addr
			}
		},
		TLSHandshakeStart:    func() { tlsStart = time.Now() },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { tlsDone = time.Now() },
		WroteRequest:         func(httptrace.WroteRequestInfo) { wrote = time.Now() },
		GotFirstResponseByte: func() { firstByte = time.Now() },
	}
	client := &http.Client{Transport: directTransport(timeout, nil), CheckRedirect: noRedirect, Timeout: timeout * 2}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, rawURL, nil)
	if err != nil {
		t.Err = err.Error()
		return t
	}
	req.Header.Set("User-Agent", version.UserAgent())
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		t.ErrKind = ClassifyErr(err)
		t.Err = err.Error()
		if strings.HasPrefix(t.ErrKind, "tls") {
			if u, perr := url.Parse(rawURL); perr == nil {
				t.CertIssuer = peekIssuer(ctx, u, timeout)
			}
		}
		return t
	}
	t.Location = resp.Header.Get("Location")
	if st := resp.TLS; st != nil {
		t.TLSVersion = tls.VersionName(st.Version)
		if len(st.PeerCertificates) > 0 {
			c := st.PeerCertificates[0]
			t.CertIssuer = issuerName(c)
			t.CertExpiresDays = int(time.Until(c.NotAfter).Hours() / 24)
		}
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()

	span := func(a, b time.Time) float64 {
		if a.IsZero() || b.IsZero() || b.Before(a) {
			return 0
		}
		return ms(b.Sub(a))
	}
	t.OK = resp.StatusCode < 500
	t.Status = resp.StatusCode
	t.DNSMs = span(dnsStart, dnsDone)
	t.ConnectMs = span(connStart, connDone)
	t.TLSMs = span(tlsStart, tlsDone)
	t.ServerMs = span(wrote, firstByte)
	t.TotalMs = span(start, firstByte)
	return t
}
