package target

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/strlenstrlen/netdiag/internal/probe"
)

// Reference is a known-good site checked alongside the target, so a failure
// can be pinned on the site or on the network.
const Reference = "https://www.google.com/generate_204"

type SiteReport struct {
	Input      string            `json:"input"`
	URL        string            `json:"url"`
	Host       string            `json:"host"`
	Port       string            `json:"port"`
	DNS        DNSReport         `json:"dns"`
	Connect    []probe.TCPResult `json:"connect"` // one per resolved address (up to 2 IPv4 + 2 IPv6)
	Ping       *probe.PingResult `json:"ping,omitempty"`
	HTTP       probe.HTTPTiming  `json:"http"`
	Reference  probe.HTTPTiming  `json:"reference"`
	Conclusion Conclusion        `json:"conclusion"`
}

// NormalizeURL turns "example.com", "example.com/path" or a full URL into
// a URL, defaulting to https.
func NormalizeURL(in string) (*url.URL, error) {
	s := strings.TrimSpace(in)
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("%q has no host name", in)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q (use http or https)", u.Scheme)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}

// CheckSite checks one site. hasIPv6 says whether this computer has an
// IPv6 route; without one, IPv6 addresses are skipped rather than reported
// as failures.
func CheckSite(ctx context.Context, input string, configured, public []string, hasIPv6 bool, timeout time.Duration) (SiteReport, error) {
	u, err := NormalizeURL(input)
	if err != nil {
		return SiteReport{}, err
	}
	r := SiteReport{Input: input, URL: u.String(), Host: u.Hostname(), Port: u.Port()}
	if r.Port == "" {
		r.Port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); r.Reference = probe.HTTPTime(ctx, Reference, timeout) }()
	go func() {
		defer wg.Done()
		if ip := net.ParseIP(r.Host); ip != nil {
			r.DNS = DNSReport{Name: r.Host, Answers: []Answer{{Server: "system", Kind: "system", OK: true, Addrs: []string{r.Host}}},
				Conclusion: Conclusion{Status: "ok", Headline: "IP address given; no DNS needed"}}
		} else {
			r.DNS = CheckDNS(ctx, r.Host, configured, public, timeout)
		}
	}()
	wg.Wait()

	// Connect to each address the system resolver returned (or public DNS,
	// if the system resolver failed), so IPv4 and IPv6 are both tried.
	addrs := systemAddrs(r.DNS, hasIPv6)
	if len(addrs) > 0 {
		r.Connect = make([]probe.TCPResult, len(addrs))
		for i, a := range addrs {
			wg.Add(1)
			go func() { defer wg.Done(); r.Connect[i] = probe.TCPConnect(ctx, net.JoinHostPort(a, r.Port), timeout) }()
		}
		wg.Add(2)
		go func() {
			defer wg.Done()
			p := probe.Ping(ctx, addrs[0], 4, 200*time.Millisecond, time.Second)
			r.Ping = &p
		}()
		go func() { defer wg.Done(); r.HTTP = probe.HTTPTime(ctx, r.URL, timeout*2) }()
		wg.Wait()
	}
	r.Conclusion = concludeSite(r)
	return r, nil
}

func systemAddrs(d DNSReport, hasIPv6 bool) []string {
	var src []string
	for _, a := range d.Answers {
		if a.Kind == "system" && a.OK && !a.Sinkhole {
			src = a.Addrs
		}
	}
	if len(src) == 0 {
		for _, a := range d.Answers {
			if a.Kind == "public" && a.OK {
				src = a.Addrs
				break
			}
		}
	}
	var v4, v6 []string
	for _, a := range src {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			v4 = append(v4, a)
		} else if hasIPv6 {
			v6 = append(v6, a)
		}
	}
	return append(first(v4, 2), first(v6, 2)...)
}

const (
	ownerSite    = "The website's operators"
	ownerNetwork = "Network admin / security software"
)

func concludeSite(r SiteReport) Conclusion {
	host := r.Host
	refOK := r.Reference.OK
	h := r.HTTP

	// DNS first: if the name doesn't resolve, nothing else ran.
	if d := r.DNS.Conclusion; d.Status == "fail" {
		return d
	}
	if len(r.Connect) == 0 {
		return Conclusion{Status: "fail", Headline: "Couldn't find an address for " + host}
	}
	// A reference that failed its certificate check still connected, so
	// that's interception (handled below), not a dead connection.
	if !refOK && !h.OK && !strings.HasPrefix(r.Reference.ErrKind, "tls") {
		return Conclusion{Status: "fail", Owner: "The network you're on",
			Headline:  "Your internet connection isn't working, so this site can't be checked",
			Evidence:  []string{"A reference site failed too (" + nz(r.Reference.ErrKind, "no response") + ")"},
			NextSteps: []string{"Run netdiag without arguments to find out why"}}
	}

	var v4OK, v6OK, v4N, v6N int
	refused := 0
	for _, c := range r.Connect {
		host, _, _ := net.SplitHostPort(c.Target)
		isV4 := net.ParseIP(host).To4() != nil
		if isV4 {
			v4N++
		} else {
			v6N++
		}
		if c.Connected {
			if isV4 {
				v4OK++
			} else {
				v6OK++
			}
		}
		if c.Refused {
			refused++
		}
	}
	ev := []string{}
	if refOK {
		ev = append(ev, "A reference site loads fine from this network")
	}
	switch {
	case v4OK+v6OK == 0 && refused > 0:
		return Conclusion{Status: "fail", Owner: ownerSite,
			Headline:  fmt.Sprintf("%s refuses connections on port %s", host, r.Port),
			Evidence:  append(ev, fmt.Sprintf("%d of %d addresses actively refused the connection: the server is reachable but the service isn't running", refused, len(r.Connect))),
			NextSteps: []string{"The site is likely down; try again later or contact its operators"}}
	case v4OK+v6OK == 0:
		return Conclusion{Status: "fail", Owner: ownerSite,
			Headline: fmt.Sprintf("%s isn't responding", host),
			Evidence: append(ev, fmt.Sprintf("%s accepted a connection (%s)", noneOf(len(r.Connect)), errKinds(r.Connect))),
			NextSteps: []string{
				"Check from a phone on mobile data: if it fails there too, the site is down",
				"If it works elsewhere, the site or a firewall may be blocking your network or VPN",
			}}
	}

	// TLS problems.
	if strings.HasPrefix(h.ErrKind, "tls") {
		refTLS := r.Reference.OK || !strings.HasPrefix(r.Reference.ErrKind, "tls")
		issuer := ""
		if h.CertIssuer != "" {
			issuer = " (issued by " + h.CertIssuer + ")"
		}
		switch {
		case h.ErrKind == "tls-untrusted" && !refTLS:
			return Conclusion{Status: "fail", Owner: ownerNetwork,
				Headline:  "Secure connections are being intercepted on this network",
				Evidence:  []string{"Both " + host + " and a reference site presented untrusted certificates" + issuer},
				NextSteps: []string{"Security software or a corporate proxy is inspecting HTTPS; ask IT to install its certificate"}}
		case h.ErrKind == "tls-untrusted":
			return Conclusion{Status: "fail", Owner: ownerSite,
				Headline:  host + "'s security certificate isn't trusted",
				Evidence:  append(ev, "It presented a self-signed certificate or one from an unknown authority"+issuer+"; the reference site's certificate was fine, so this network isn't intercepting connections"),
				NextSteps: []string{"Only the site's operators can fix this; don't enter passwords or payment details on it"}}
		case h.ErrKind == "tls-expired":
			return Conclusion{Status: "fail", Owner: ownerSite,
				Headline:  host + "'s security certificate has expired",
				Evidence:  append(ev, "The certificate failed its date check"+issuer+"; the reference site's didn't, so this computer's clock is fine"),
				NextSteps: []string{"Only the site's operators can fix this; avoid entering passwords until they do"}}
		case h.ErrKind == "tls-hostname":
			return Conclusion{Status: "fail", Owner: ownerSite,
				Headline:  host + "'s certificate is for a different name",
				Evidence:  append(ev, "The server presented a certificate that doesn't cover "+host+issuer),
				NextSteps: []string{"Check the address; if it's right, the site is misconfigured"}}
		default:
			return Conclusion{Status: "fail", Owner: ownerSite,
				Headline:  host + "'s secure connection failed",
				Evidence:  append(ev, "TLS error: "+h.ErrKind+issuer),
				NextSteps: []string{"If other people can open it, security software on this computer may be interfering"}}
		}
	}
	if !h.OK && h.Status == 0 {
		return Conclusion{Status: "fail", Owner: ownerSite,
			Headline: host + " accepted the connection but didn't respond",
			Evidence: append(ev, "Request failed: "+nz(h.ErrKind, "no response")),
		}
	}

	ev = append(ev, fmt.Sprintf("Connected to %s and got HTTP %d in %.0f ms (DNS %.0f · connect %.0f · TLS %.0f · server %.0f ms)",
		nz(h.RemoteAddr, host), h.Status, h.TotalMs, h.DNSMs, h.ConnectMs, h.TLSMs, h.ServerMs))
	var c Conclusion
	switch {
	case h.Status >= 500:
		c = Conclusion{Status: "fail", Owner: ownerSite,
			Headline:  fmt.Sprintf("%s is having server problems (HTTP %d)", host, h.Status),
			Evidence:  ev,
			NextSteps: []string{"The problem is on the site's side; try again later"}}
	case h.Status == 403 || h.Status == 429 || h.Status == 451:
		c = Conclusion{Status: "warn", Owner: ownerSite,
			Headline: fmt.Sprintf("%s is refusing requests from here (HTTP %d)", host, h.Status),
			Evidence: append(ev, "This status can mean the site blocks automated checks like this one, your network, your VPN or your country"),
			NextSteps: []string{
				"Try it in a browser; if it fails there too, try without a VPN or from mobile data",
			}}
	case h.ServerMs > 1000 && r.Reference.OK && h.ServerMs > 3*r.Reference.ServerMs:
		c = Conclusion{Status: "warn", Owner: ownerSite,
			Headline:  fmt.Sprintf("%s is slow to respond", host),
			Evidence:  append(ev, fmt.Sprintf("Its server took %.0f ms to answer; the reference site took %.0f ms, so your connection isn't the cause", h.ServerMs, r.Reference.ServerMs)),
			NextSteps: []string{"The delay is on the site's side"}}
	default:
		c = Conclusion{Status: "ok", Headline: fmt.Sprintf("%s works from this network", host), Evidence: ev}
		if h.Location != "" {
			c.Evidence = append(c.Evidence, "It redirects to "+h.Location)
		}
	}
	if v4N > 0 && v6N > 0 && v6OK == 0 && v4OK > 0 {
		c.Evidence = append(c.Evidence, "Its IPv6 addresses didn't accept connections while IPv4 did; apps may pause before falling back to IPv4")
		if c.Status == "ok" {
			c.Status = "warn"
			c.Owner = "Router / internet provider (IPv6)"
		}
	}
	if h.CertExpiresDays > 0 && h.CertExpiresDays <= 14 {
		c.Evidence = append(c.Evidence, fmt.Sprintf("Its certificate expires in %d days", h.CertExpiresDays))
	}
	if d := r.DNS.Conclusion; d.Status == "warn" {
		c.Evidence = append(c.Evidence, d.Evidence[len(d.Evidence)-1])
	}
	return c
}

func noneOf(n int) string {
	if n == 1 {
		return "Its only address never"
	}
	return fmt.Sprintf("None of its %d addresses", n)
}

func errKinds(cs []probe.TCPResult) string {
	seen := map[string]bool{}
	var out []string
	for _, c := range cs {
		k := nz(c.ErrKind, "failed")
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return strings.Join(out, ", ")
}
