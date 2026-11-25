// Package target checks one named thing (a DNS name, a website) and
// concludes whether the problem is that thing or the user's network.
package target

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/strlenstrlen/netdiag/internal/probe"
)

// Conclusion mirrors the main verdict's shape for a single-target check.
type Conclusion struct {
	Status    string   `json:"status"` // "ok", "warn" or "fail"
	Headline  string   `json:"headline"`
	Owner     string   `json:"owner,omitempty"`
	Evidence  []string `json:"evidence,omitempty"`
	NextSteps []string `json:"next_steps,omitempty"`
}

type Answer struct {
	Server   string   `json:"server"` // "system" or an IP
	Kind     string   `json:"kind"`   // "system", "configured" or "public"
	OK       bool     `json:"ok"`
	NotFound bool     `json:"not_found,omitempty"`
	Addrs    []string `json:"addrs,omitempty"`
	Sinkhole bool     `json:"sinkhole,omitempty"` // answered 0.0.0.0, 127.x, :: — how DNS filters block names
	Private  bool     `json:"private,omitempty"`  // answered only private addresses (split-horizon or filter)
	RTTMs    float64  `json:"rtt_ms"`
	ErrKind  string   `json:"error_kind,omitempty"`
}

func (a Answer) label() string {
	if a.Kind == "system" {
		return "this computer's resolver"
	}
	return a.Server + " (" + a.Kind + ")"
}

type DNSReport struct {
	Name       string     `json:"name"`
	CNAME      string     `json:"cname,omitempty"`
	Answers    []Answer   `json:"answers"`
	Hijackers  []string   `json:"nxdomain_hijackers,omitempty"` // resolvers that answer for names that don't exist
	Conclusion Conclusion `json:"conclusion"`
}

var publicNames = map[string]string{"1.1.1.1": "Cloudflare", "8.8.8.8": "Google", "9.9.9.9": "Quad9"}

func CheckDNS(ctx context.Context, name string, configured, public []string, timeout time.Duration) DNSReport {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	r := DNSReport{Name: name}

	type job struct{ server, kind string }
	jobs := []job{{"system", "system"}}
	for _, s := range configured {
		jobs = append(jobs, job{s, "configured"})
	}
	for _, s := range public {
		jobs = append(jobs, job{s, "public"})
	}
	r.Answers = make([]Answer, len(jobs))
	hijack := make([]bool, len(jobs))
	bogus := randomLabel() + ".google.com" // a name that can't exist
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(2)
		go func() {
			defer wg.Done()
			var res probe.DNSResult
			if j.server == "system" {
				res = probe.LookupSystem(ctx, name, timeout)
			} else {
				res = probe.LookupVia(ctx, j.server, name, timeout)
			}
			a := Answer{Server: j.server, Kind: j.kind, OK: res.OK, NotFound: res.NotFound, Addrs: res.Addrs, RTTMs: res.RTTMs, ErrKind: res.ErrKind}
			a.Sinkhole, a.Private = classifyAddrs(res.Addrs)
			r.Answers[i] = a
		}()
		go func() {
			defer wg.Done()
			if j.kind == "public" {
				return
			}
			var res probe.DNSResult
			if j.server == "system" {
				res = probe.LookupSystem(ctx, bogus, timeout)
			} else {
				res = probe.LookupVia(ctx, j.server, bogus, timeout)
			}
			hijack[i] = res.OK
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		if cn, err := net.DefaultResolver.LookupCNAME(c, name); err == nil && strings.TrimSuffix(cn, ".") != name {
			r.CNAME = strings.TrimSuffix(cn, ".")
		}
	}()
	wg.Wait()
	for i, h := range hijack {
		if h {
			r.Hijackers = append(r.Hijackers, r.Answers[i].label())
		}
	}
	r.Conclusion = concludeDNS(r)
	return r
}

// classifyAddrs flags DNS-filter sinkhole answers and private-only answers.
func classifyAddrs(addrs []string) (sinkhole, private bool) {
	if len(addrs) == 0 {
		return false, false
	}
	sink, priv := true, true
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			continue
		}
		if !(ip.IsUnspecified() || ip.IsLoopback()) {
			sink = false
		}
		if !(ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast()) {
			priv = false
		}
	}
	return sink, priv && !sink
}

func concludeDNS(r DNSReport) Conclusion {
	var sys *Answer
	var pubOK, pubNX, pubTotal int
	for i, a := range r.Answers {
		switch a.Kind {
		case "system":
			sys = &r.Answers[i]
		case "public":
			pubTotal++
			if a.OK && !a.Sinkhole {
				pubOK++
			}
			if a.NotFound {
				pubNX++
			}
		}
	}
	var c Conclusion
	pubAddrs := ""
	for _, a := range r.Answers {
		if a.Kind == "public" && a.OK {
			pubAddrs = strings.Join(first(a.Addrs, 2), ", ")
			break
		}
	}

	switch {
	case sys == nil:
		c = Conclusion{Status: "fail", Headline: "Couldn't run the DNS check"}
	case pubTotal > 0 && pubNX == pubTotal && (sys.NotFound || !sys.OK):
		c = Conclusion{Status: "fail", Owner: "Whoever gave you the address",
			Headline:  fmt.Sprintf("%s doesn't exist", r.Name),
			Evidence:  []string{"Every DNS server, including public ones, says there is no such name"},
			NextSteps: []string{"Check the spelling", "If the name used to work, its domain registration or DNS records may have lapsed"}}
	case sys.Sinkhole || ((sys.NotFound || !sys.OK) && pubOK > 0 && sys.ErrKind != "dns-timeout" && sys.ErrKind != "timeout"):
		how := "says the name doesn't exist"
		if sys.Sinkhole {
			how = fmt.Sprintf("answers %s, an address DNS filters use to block names", strings.Join(sys.Addrs, ", "))
		}
		c = Conclusion{Status: "fail", Owner: "Network admin / DNS filter",
			Headline: fmt.Sprintf("Your DNS is blocking %s", r.Name),
			Evidence: []string{
				"This computer's DNS " + how,
				fmt.Sprintf("Public DNS resolves it normally (%s)", pubAddrs),
			},
			NextSteps: []string{
				"A DNS filter (Pi-hole, NextDNS, router parental controls or a work policy) is blocking it",
				"If it should be allowed, ask whoever manages that filter to allow it",
			}}
	case !sys.OK && pubOK > 0:
		c = Conclusion{Status: "fail", Owner: "DNS provider (router or ISP)",
			Headline:  fmt.Sprintf("Your DNS server isn't answering for %s, but public DNS is", r.Name),
			Evidence:  []string{fmt.Sprintf("This computer's resolver: %s; public DNS returned %s", nz(sys.ErrKind, "no answer"), pubAddrs)},
			NextSteps: []string{"Restart the router", "As a workaround, set DNS to 1.1.1.1 and 8.8.8.8"}}
	case !sys.OK:
		c = Conclusion{Status: "fail", Owner: "The network you're on",
			Headline:  "No DNS server answered",
			Evidence:  []string{fmt.Sprintf("This computer's resolver: %s; public DNS servers didn't answer either", nz(sys.ErrKind, "no answer"))},
			NextSteps: []string{"Run netdiag without arguments to check your connection"}}
	default:
		c = Conclusion{Status: "ok", Headline: fmt.Sprintf("%s resolves normally", r.Name),
			Evidence: []string{fmt.Sprintf("This computer's resolver answered %s in %.0f ms", strings.Join(first(sys.Addrs, 3), ", "), sys.RTTMs)}}
		if sys.Private && pubOK > 0 {
			c.Evidence = append(c.Evidence, fmt.Sprintf("It answered with a private address while public DNS returns %s: normal for internal (split-horizon) names, otherwise a DNS filter or misconfiguration", pubAddrs))
		}
		if r.CNAME != "" {
			c.Evidence = append(c.Evidence, "It's an alias for "+r.CNAME)
		}
		if pubOK > 0 && !sameNetwork(sys.Addrs, r.Answers) {
			c.Evidence = append(c.Evidence, "Different resolvers returned different addresses; that's normal for sites on content delivery networks")
		}
	}
	if len(r.Hijackers) > 0 {
		if c.Status == "ok" {
			c.Status = "warn"
		}
		c.Evidence = append(c.Evidence, fmt.Sprintf("%s returns addresses even for names that don't exist (NXDOMAIN hijacking), which can confuse apps and hide typos",
			strings.Join(r.Hijackers, " and ")))
		c.NextSteps = append(c.NextSteps, "Turn off \"DNS assist\" or \"search help\" in your ISP account, or use public DNS")
	}
	return c
}

// sameNetwork is true when the system's answers overlap any public answer.
func sameNetwork(sys []string, answers []Answer) bool {
	set := map[string]bool{}
	for _, a := range sys {
		set[a] = true
	}
	for _, a := range answers {
		if a.Kind == "public" {
			for _, x := range a.Addrs {
				if set[x] {
					return true
				}
			}
		}
	}
	return false
}

func first(xs []string, n int) []string {
	if len(xs) > n {
		return xs[:n]
	}
	return xs
}

func nz(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func randomLabel() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "netdiag-" + hex.EncodeToString(b)
}

// PublicName returns a provider name for a well-known public resolver.
func PublicName(ip string) string { return publicNames[ip] }
