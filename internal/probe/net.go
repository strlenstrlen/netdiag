package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/strlenstrlen/netdiag/internal/version"
)

func ms(d time.Duration) float64 { return round1(float64(d.Microseconds()) / 1000) }

// sleepStop waits d, returning false early if ctx is done or stop closes.
func sleepStop(ctx context.Context, stop <-chan struct{}, d time.Duration) bool {
	if d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-stop: // nil channel: never ready
			return false
		case <-t.C:
		}
	}
	if ctx.Err() != nil {
		return false
	}
	select {
	case <-stop:
		return false
	default:
		return true
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// ---- TCP ----

type TCPResult struct {
	Target    string  `json:"target"`
	Connected bool    `json:"connected"`
	Refused   bool    `json:"refused,omitempty"` // host answered with RST: it is alive
	RTTMs     float64 `json:"rtt_ms,omitempty"`
	ErrKind   string  `json:"error_kind,omitempty"`
	Err       string  `json:"error,omitempty"`
}

// HostAlive is true when the host answered at all, including a refusal.
func (t TCPResult) HostAlive() bool { return t.Connected || t.Refused }

func TCPConnect(ctx context.Context, target string, timeout time.Duration) TCPResult {
	r := TCPResult{Target: target}
	d := net.Dialer{Timeout: timeout}
	start := time.Now()
	c, err := d.DialContext(ctx, "tcp", target)
	r.RTTMs = ms(time.Since(start))
	if err != nil {
		r.Refused = isRefused(err)
		r.ErrKind = ClassifyErr(err)
		r.Err = err.Error()
		if !r.Refused {
			r.RTTMs = 0
		}
		return r
	}
	c.Close()
	r.Connected = true
	return r
}

// ---- DNS ----

type DNSResult struct {
	Server   string   `json:"server"` // "system" or a server IP
	Name     string   `json:"name"`
	OK       bool     `json:"ok"`
	NotFound bool     `json:"not_found,omitempty"`
	Addrs    []string `json:"addrs,omitempty"`
	RTTMs    float64  `json:"rtt_ms"`
	ErrKind  string   `json:"error_kind,omitempty"`
	Err      string   `json:"error,omitempty"`
}

// LookupSystem resolves through the OS resolver: the same path browsers
// and apps use, including caches, VPN split DNS and /etc/hosts.
func LookupSystem(ctx context.Context, name string, timeout time.Duration) DNSResult {
	return lookup(ctx, net.DefaultResolver, "system", name, timeout)
}

// LookupVia sends queries straight to one DNS server over UDP/TCP port 53,
// bypassing the OS resolver.
func LookupVia(ctx context.Context, server, name string, timeout time.Duration) DNSResult {
	addr := net.JoinHostPort(server, "53")
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, addr)
		},
	}
	if !strings.HasSuffix(name, ".") {
		name += "." // fully qualified: no search-domain expansion
	}
	res := lookup(ctx, r, server, name, timeout)
	res.Name = strings.TrimSuffix(name, ".")
	return res
}

func lookup(ctx context.Context, r *net.Resolver, server, name string, timeout time.Duration) DNSResult {
	res := DNSResult{Server: server, Name: name}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	addrs, err := r.LookupIPAddr(ctx, name)
	res.RTTMs = ms(time.Since(start))
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			res.NotFound = true
		}
		res.ErrKind = ClassifyErr(err)
		res.Err = err.Error()
		return res
	}
	res.OK = len(addrs) > 0
	for _, a := range addrs {
		res.Addrs = append(res.Addrs, a.IP.String())
	}
	return res
}

// ---- HTTP / HTTPS ----

type CaptiveResult struct {
	URL       string  `json:"url"`
	Reached   bool    `json:"reached"`  // got any HTTP response
	Expected  bool    `json:"expected"` // response matched the known answer
	Portal    bool    `json:"portal"`   // got a response, but not the known answer
	Status    int     `json:"status,omitempty"`
	Location  string  `json:"redirect,omitempty"`
	RTTMs     float64 `json:"rtt_ms,omitempty"`
	SkewSec   float64 `json:"clock_skew_sec,omitempty"`
	SkewKnown bool    `json:"clock_skew_known,omitempty"`
	ErrKind   string  `json:"error_kind,omitempty"`
	Err       string  `json:"error,omitempty"`
}

func directTransport(timeout time.Duration, tlsCfg *tls.Config) *http.Transport {
	return &http.Transport{
		Proxy:               nil, // test the direct path; proxies are reported separately
		DialContext:         (&net.Dialer{Timeout: timeout}).DialContext,
		TLSHandshakeTimeout: timeout,
		TLSClientConfig:     tlsCfg,
		DisableKeepAlives:   true,
	}
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func CaptiveCheck(ctx context.Context, rawURL string, expectStatus int, expectBody string, timeout time.Duration) CaptiveResult {
	r := CaptiveResult{URL: rawURL}
	client := &http.Client{Transport: directTransport(timeout, nil), CheckRedirect: noRedirect, Timeout: timeout * 2}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		r.Err = err.Error()
		return r
	}
	req.Header.Set("User-Agent", version.UserAgent())
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		r.ErrKind = ClassifyErr(err)
		r.Err = err.Error()
		return r
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	r.RTTMs = ms(time.Since(start))
	r.Reached = true
	r.Status = resp.StatusCode
	r.Location = resp.Header.Get("Location")
	r.SkewSec, r.SkewKnown = clockSkew(resp)
	r.Expected = resp.StatusCode == expectStatus && (expectBody == "" || strings.Contains(string(body), expectBody))
	r.Portal = !r.Expected
	return r
}

type HTTPSResult struct {
	URL       string  `json:"url"`
	ByIP      bool    `json:"by_ip"` // URL host is an IP literal (no DNS needed)
	OK        bool    `json:"ok"`
	Status    int     `json:"status,omitempty"`
	RTTMs     float64 `json:"rtt_ms,omitempty"`
	Issuer    string  `json:"cert_issuer,omitempty"`
	SkewSec   float64 `json:"clock_skew_sec,omitempty"`
	SkewKnown bool    `json:"clock_skew_known,omitempty"`
	ErrKind   string  `json:"error_kind,omitempty"`
	Err       string  `json:"error,omitempty"`
}

func HTTPSCheck(ctx context.Context, rawURL string, timeout time.Duration) HTTPSResult {
	r := HTTPSResult{URL: rawURL}
	u, err := url.Parse(rawURL)
	if err != nil {
		r.Err = err.Error()
		return r
	}
	r.ByIP = net.ParseIP(u.Hostname()) != nil
	client := &http.Client{Transport: directTransport(timeout, nil), CheckRedirect: noRedirect, Timeout: timeout * 2}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	req.Header.Set("User-Agent", version.UserAgent())
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		r.ErrKind = ClassifyErr(err)
		r.Err = err.Error()
		if strings.HasPrefix(r.ErrKind, "tls") {
			r.Issuer = peekIssuer(ctx, u, timeout)
		}
		return r
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	r.RTTMs = ms(time.Since(start))
	r.Status = resp.StatusCode
	r.OK = resp.StatusCode < 500
	r.SkewSec, r.SkewKnown = clockSkew(resp)
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		r.Issuer = issuerName(resp.TLS.PeerCertificates[0])
	}
	return r
}

// peekIssuer re-handshakes without verification only to read who issued
// the certificate we were shown. Used when verification already failed, to
// identify interception proxies.
func peekIssuer(ctx context.Context, u *url.URL, timeout time.Duration) string {
	port := u.Port()
	if port == "" {
		port = "443"
	}
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config:    &tls.Config{ServerName: u.Hostname(), InsecureSkipVerify: true}, //nolint:gosec // inspection only, no data sent
	}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return ""
	}
	defer c.Close()
	certs := c.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return ""
	}
	return issuerName(certs[0])
}

func issuerName(c *x509.Certificate) string {
	parts := append([]string{}, c.Issuer.Organization...)
	if c.Issuer.CommonName != "" {
		parts = append(parts, c.Issuer.CommonName)
	}
	return strings.Join(parts, " / ")
}

// clockSkew compares the server's Date header to local time. Positive means
// the local clock is behind. Date has one-second resolution.
func clockSkew(resp *http.Response) (float64, bool) {
	d := resp.Header.Get("Date")
	if d == "" {
		return 0, false
	}
	t, err := http.ParseTime(d)
	if err != nil {
		return 0, false
	}
	return t.Sub(time.Now()).Seconds(), true
}

// isRefused recognizes "connection refused" on every OS; Windows reports
// it as WSAECONNREFUSED (10061), which syscall.ECONNREFUSED doesn't match.
func isRefused(err error) bool {
	var errno syscall.Errno
	return errors.Is(err, syscall.ECONNREFUSED) || (errors.As(err, &errno) && errno == 10061)
}

// ClassifyErr maps network errors to a small set of kinds the verdict
// engine reasons about.
func ClassifyErr(err error) string {
	if err == nil {
		return ""
	}
	var (
		unknownCA x509.UnknownAuthorityError
		invalid   x509.CertificateInvalidError
		hostname  x509.HostnameError
		dnsErr    *net.DNSError
		recErr    tls.RecordHeaderError
		certErr   *tls.CertificateVerificationError
	)
	switch {
	case errors.As(err, &unknownCA):
		return "tls-untrusted"
	case errors.As(err, &invalid):
		if invalid.Reason == x509.Expired {
			return "tls-expired"
		}
		return "tls-invalid"
	case errors.As(err, &hostname):
		return "tls-hostname"
	case errors.As(err, &certErr):
		return "tls-invalid"
	case errors.As(err, &recErr):
		return "tls-protocol"
	case errors.As(err, &dnsErr):
		if dnsErr.IsTimeout {
			return "dns-timeout"
		}
		if dnsErr.IsNotFound {
			return "dns-notfound"
		}
		return "dns"
	case isRefused(err):
		return "refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "reset"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "unreachable"
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	if strings.Contains(err.Error(), "tls:") {
		return "tls-protocol"
	}
	return "other"
}
