package target

import (
	"strings"
	"testing"

	"github.com/strlenstrlen/netdiag/internal/probe"
)

func ans(server, kind string, addrs ...string) Answer {
	a := Answer{Server: server, Kind: kind, OK: len(addrs) > 0, Addrs: addrs, RTTMs: 20}
	a.Sinkhole, a.Private = classifyAddrs(addrs)
	return a
}

func nx(server, kind string) Answer {
	return Answer{Server: server, Kind: kind, NotFound: true, ErrKind: "dns-notfound"}
}

func TestDNSConclusions(t *testing.T) {
	pub := []Answer{ans("1.1.1.1", "public", "93.184.215.14"), ans("8.8.8.8", "public", "93.184.215.14")}
	tests := []struct {
		name     string
		answers  []Answer
		hijack   []string
		status   string
		headline string
	}{
		{"normal", append([]Answer{ans("system", "system", "93.184.215.14")}, pub...), nil, "ok", "resolves normally"},
		{"sinkholed by a filter", append([]Answer{ans("system", "system", "0.0.0.0")}, pub...), nil, "fail", "Your DNS is blocking"},
		{"filter answers no such name", append([]Answer{nx("system", "system")}, pub...), nil, "fail", "Your DNS is blocking"},
		{"name doesn't exist", []Answer{nx("system", "system"), nx("1.1.1.1", "public"), nx("8.8.8.8", "public")}, nil, "fail", "doesn't exist"},
		{"own DNS times out", append([]Answer{{Server: "system", Kind: "system", ErrKind: "dns-timeout"}}, pub...), nil, "fail", "isn't answering"},
		{"ISP hijacks typos", append([]Answer{ans("system", "system", "93.184.215.14")}, pub...), []string{"192.168.1.1 (configured)"}, "warn", "resolves normally"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := concludeDNS(DNSReport{Name: "example.com", Answers: tc.answers, Hijackers: tc.hijack})
			if c.Status != tc.status || !strings.Contains(c.Headline, tc.headline) {
				t.Errorf("got %s %q", c.Status, c.Headline)
			}
		})
	}
	if s, p := classifyAddrs([]string{"10.1.2.3"}); s || !p {
		t.Error("private answer should be flagged private, not sinkhole")
	}
}

func site(mod func(r *SiteReport)) Conclusion {
	r := SiteReport{
		Host: "shop.example", Port: "443",
		DNS:       DNSReport{Conclusion: Conclusion{Status: "ok"}},
		Connect:   []probe.TCPResult{{Target: "93.184.215.14:443", Connected: true, RTTMs: 20}},
		HTTP:      probe.HTTPTiming{OK: true, Status: 200, TotalMs: 120, ServerMs: 50},
		Reference: probe.HTTPTiming{OK: true, Status: 204, ServerMs: 30},
	}
	mod(&r)
	return concludeSite(r)
}

func TestSiteConclusions(t *testing.T) {
	tests := []struct {
		name     string
		mod      func(r *SiteReport)
		status   string
		headline string
	}{
		{"works", func(r *SiteReport) {}, "ok", "works from this network"},
		{"server error", func(r *SiteReport) { r.HTTP.Status, r.HTTP.OK = 503, false }, "fail", "server problems"},
		{"blocked", func(r *SiteReport) { r.HTTP.Status = 403 }, "warn", "refusing requests"},
		{"slow server", func(r *SiteReport) { r.HTTP.ServerMs = 2500 }, "warn", "slow to respond"},
		{"down", func(r *SiteReport) {
			r.Connect[0] = probe.TCPResult{Target: r.Connect[0].Target, ErrKind: "timeout"}
			r.HTTP = probe.HTTPTiming{ErrKind: "timeout"}
		}, "fail", "isn't responding"},
		{"refused", func(r *SiteReport) {
			r.Connect[0] = probe.TCPResult{Target: r.Connect[0].Target, Refused: true}
			r.HTTP = probe.HTTPTiming{ErrKind: "refused"}
		}, "fail", "refuses connections"},
		{"our internet is down", func(r *SiteReport) {
			r.HTTP = probe.HTTPTiming{ErrKind: "timeout"}
			r.Reference = probe.HTTPTiming{ErrKind: "timeout"}
		}, "fail", "connection isn't working"},
		{"expired cert", func(r *SiteReport) { r.HTTP = probe.HTTPTiming{ErrKind: "tls-expired"} }, "fail", "has expired"},
		{"self-signed", func(r *SiteReport) { r.HTTP = probe.HTTPTiming{ErrKind: "tls-untrusted"} }, "fail", "isn't trusted"},
		{"interception", func(r *SiteReport) {
			r.HTTP = probe.HTTPTiming{ErrKind: "tls-untrusted", CertIssuer: "Contoso Filter CA"}
			r.Reference = probe.HTTPTiming{ErrKind: "tls-untrusted"}
		}, "fail", "being intercepted"},
		{"IPv6 broken for this site", func(r *SiteReport) {
			r.Connect = append(r.Connect, probe.TCPResult{Target: "[2606:2800::1]:443", ErrKind: "timeout"})
		}, "warn", "works from this network"},
		{"DNS blocks it", func(r *SiteReport) {
			r.DNS.Conclusion = Conclusion{Status: "fail", Headline: "Your DNS is blocking shop.example"}
		}, "fail", "blocking"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := site(tc.mod)
			if c.Status != tc.status || !strings.Contains(c.Headline, tc.headline) {
				t.Errorf("got %s %q", c.Status, c.Headline)
			}
		})
	}
}

func TestNormalizeURL(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":               "https://example.com/",
		"http://example.com:8080/x": "http://example.com:8080/x",
		" example.com/path ":        "https://example.com/path",
	} {
		u, err := NormalizeURL(in)
		if err != nil || u.String() != want {
			t.Errorf("NormalizeURL(%q) = %v, %v", in, u, err)
		}
	}
	if _, err := NormalizeURL("ftp://example.com"); err == nil {
		t.Error("ftp should be rejected")
	}
}
