// Package ladder runs the stage-1 connectivity checks. All probes run
// concurrently (about 5 seconds total); the verdict engine reads the results
// in ladder order: interface → router → internet → DNS → captive portal → HTTPS.
package ladder

import (
	"context"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/strlenstrlen/netdiag/internal/config"
	"github.com/strlenstrlen/netdiag/internal/probe"
	"github.com/strlenstrlen/netdiag/internal/quality"
	"github.com/strlenstrlen/netdiag/internal/snapshot"
	"github.com/strlenstrlen/netdiag/internal/speed"
)

type Results struct {
	Symptom    string            `json:"symptom,omitempty"`
	StartedAt  time.Time         `json:"started_at"`
	DurationMs float64           `json:"duration_ms"`
	Snapshot   snapshot.Snapshot `json:"snapshot"`

	GatewayTested bool              `json:"gateway_tested"`
	GatewayPing   probe.PingResult  `json:"gateway_ping"`
	GatewayTCP    []probe.TCPResult `json:"gateway_tcp,omitempty"`

	InternetPing []probe.PingResult `json:"internet_ping"`
	InternetTCP  []probe.TCPResult  `json:"internet_tcp"`

	IPv6Tested    bool               `json:"ipv6_tested"`
	InternetPing6 []probe.PingResult `json:"internet_ping_v6,omitempty"`
	InternetTCP6  []probe.TCPResult  `json:"internet_tcp_v6,omitempty"`

	DNSSystem     []probe.DNSResult `json:"dns_system"`
	DNSConfigured []probe.DNSResult `json:"dns_configured"`
	DNSPublic     []probe.DNSResult `json:"dns_public"`

	Captive []probe.CaptiveResult `json:"captive"`
	HTTPS   []probe.HTTPSResult   `json:"https"`

	ClockSkewSec   float64 `json:"clock_skew_sec"`
	ClockSkewKnown bool    `json:"clock_skew_known"`

	// Stage 2. Nil when it didn't run; QualitySkipped says why.
	Quality        *quality.Results `json:"quality,omitempty"`
	QualitySkipped string           `json:"quality_skipped,omitempty"`

	// Stage 3. Nil when it didn't run; SpeedSkipped says why.
	Speed        *speed.Results `json:"speed,omitempty"`
	SpeedSkipped string         `json:"speed_skipped,omitempty"`
}

// QualityPlan picks stage-2 targets using what stage 1 learned: hosts that
// answered ping are sampled by ICMP, hosts that only accepted TCP by TCP,
// and hosts that answered neither are left out.
func (r Results) QualityPlan(cfg config.Config) quality.Plan {
	p := quality.Plan{DNSServers: r.Snapshot.DNSServers}

	if r.GatewayTested {
		if r.GatewayPing.OK() {
			p.Router = &quality.Target{Addr: r.GatewayPing.Target, Method: "icmp"}
		} else {
			for _, t := range r.GatewayTCP {
				if t.HostAlive() {
					p.Router = &quality.Target{Addr: t.Target, Method: "tcp"}
					break
				}
			}
		}
	}

	pingOK := map[string]bool{}
	for _, x := range r.InternetPing {
		if x.OK() {
			pingOK[x.Target] = true
		}
	}
	tcpOK := map[string]string{} // host → host:port that connected
	for _, x := range r.InternetTCP {
		if x.Connected {
			tcpOK[quality.HostOnly(x.Target)] = x.Target
		}
	}
	for _, host := range cfg.QualityTargets {
		switch {
		case pingOK[host]:
			p.Internet = append(p.Internet, quality.Target{Addr: host, Method: "icmp"})
		case tcpOK[host] != "":
			p.Internet = append(p.Internet, quality.Target{Addr: tcpOK[host], Method: "tcp"})
		}
	}

	if r.IPv6Tested {
		for _, x := range r.InternetTCP6 {
			p.IPv6 = p.IPv6 || x.Connected
		}
	}
	return p
}

// Ports tried on the router. A refusal still proves the router is alive.
var gatewayPorts = []string{"53", "80", "443"}

func Run(ctx context.Context, cfg config.Config, snap snapshot.Snapshot) Results {
	r := Results{StartedAt: time.Now(), Snapshot: snap}
	timeout := cfg.ProbeTimeout()
	interval := cfg.PingInterval()

	var wg sync.WaitGroup
	do := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}

	// Router.
	if snap.DefaultRoute != nil && net.ParseIP(snap.DefaultRoute.Gateway) != nil {
		gw := snap.DefaultRoute.Gateway
		r.GatewayTested = true
		do(func() { r.GatewayPing = probe.Ping(ctx, gw, cfg.GatewayPingCount, interval, timeout) })
		r.GatewayTCP = make([]probe.TCPResult, len(gatewayPorts))
		for i, p := range gatewayPorts {
			do(func() { r.GatewayTCP[i] = probe.TCPConnect(ctx, net.JoinHostPort(gw, p), timeout) })
		}
	}

	// Internet by IP (no DNS involved).
	r.InternetPing = make([]probe.PingResult, len(cfg.PingTargets))
	for i, t := range cfg.PingTargets {
		do(func() { r.InternetPing[i] = probe.Ping(ctx, t, cfg.InternetPingCount, interval, timeout) })
	}
	r.InternetTCP = make([]probe.TCPResult, len(cfg.TCPTargets))
	for i, t := range cfg.TCPTargets {
		do(func() { r.InternetTCP[i] = probe.TCPConnect(ctx, t, timeout) })
	}

	// IPv6, only when the machine believes it has working IPv6.
	if snap.DefaultRoute6 != nil && hasGlobalIPv6(snap) {
		r.IPv6Tested = true
		r.InternetPing6 = make([]probe.PingResult, len(cfg.PingTargets6))
		for i, t := range cfg.PingTargets6 {
			do(func() { r.InternetPing6[i] = probe.Ping(ctx, t, cfg.InternetPingCount, interval, timeout) })
		}
		r.InternetTCP6 = make([]probe.TCPResult, len(cfg.TCPTargets6))
		for i, t := range cfg.TCPTargets6 {
			do(func() { r.InternetTCP6[i] = probe.TCPConnect(ctx, t, timeout) })
		}
	}

	// DNS: the OS resolver, each configured server directly, and public
	// resolvers directly. Comparing them isolates where DNS breaks.
	r.DNSSystem = make([]probe.DNSResult, len(cfg.DNSNames))
	for i, n := range cfg.DNSNames {
		do(func() { r.DNSSystem[i] = probe.LookupSystem(ctx, n, timeout) })
	}
	r.DNSConfigured = make([]probe.DNSResult, len(snap.DNSServers)*len(cfg.DNSNames))
	for si, s := range snap.DNSServers {
		for ni, n := range cfg.DNSNames {
			idx := si*len(cfg.DNSNames) + ni
			do(func() { r.DNSConfigured[idx] = probe.LookupVia(ctx, s, n, timeout) })
		}
	}
	r.DNSPublic = make([]probe.DNSResult, len(cfg.PublicDNS)*len(cfg.DNSNames))
	for si, s := range cfg.PublicDNS {
		for ni, n := range cfg.DNSNames {
			idx := si*len(cfg.DNSNames) + ni
			do(func() { r.DNSPublic[idx] = probe.LookupVia(ctx, s, n, timeout) })
		}
	}

	// Web.
	r.Captive = make([]probe.CaptiveResult, len(cfg.CaptiveChecks))
	for i, c := range cfg.CaptiveChecks {
		do(func() { r.Captive[i] = probe.CaptiveCheck(ctx, c.URL, c.ExpectStatus, c.ExpectBody, timeout) })
	}
	r.HTTPS = make([]probe.HTTPSResult, len(cfg.HTTPSChecks))
	for i, u := range cfg.HTTPSChecks {
		do(func() { r.HTTPS[i] = probe.HTTPSCheck(ctx, u, timeout) })
	}

	wg.Wait()
	r.ClockSkewSec, r.ClockSkewKnown = clockSkew(r)
	r.DurationMs = math.Round(float64(time.Since(r.StartedAt).Milliseconds()))
	return r
}

func hasGlobalIPv6(s snapshot.Snapshot) bool {
	for _, it := range s.Interfaces {
		if it.Up && it.Kind != snapshot.KindLoopback {
			for _, a := range it.IPv6 {
				// Exclude unique-local fc00::/7; it can't reach the internet.
				if !strings.HasPrefix(a, "fc") && !strings.HasPrefix(a, "fd") {
					return true
				}
			}
		}
	}
	return false
}

// clockSkew takes the median of server Date headers. CDN caches sometimes
// serve stale Date headers, so a result counts only when at least two
// sources agree within a minute of the median.
func clockSkew(r Results) (float64, bool) {
	var skews []float64
	for _, h := range r.HTTPS {
		if h.SkewKnown {
			skews = append(skews, h.SkewSec)
		}
	}
	for _, c := range r.Captive {
		if c.SkewKnown {
			skews = append(skews, c.SkewSec)
		}
	}
	if len(skews) < 2 {
		return 0, false
	}
	sort.Float64s(skews)
	med := probe.Median(skews)
	agree := 0
	for _, s := range skews {
		if math.Abs(s-med) <= 60 {
			agree++
		}
	}
	if agree < 2 {
		return 0, false
	}
	return math.Round(med) + 0, true // +0 turns -0 into 0
}
