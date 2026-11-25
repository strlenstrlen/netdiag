// Package quality is stage 2: how well the connection works, not just
// whether it works. It answers the different kinds of "slow":
//
//   - laggy / choppy calls → latency series with spike and loss timing
//   - slow to start loading → uncached DNS timing and HTTP phase timing
//   - slow on some networks → IPv4 vs IPv6 comparison
//
// Throughput (download/upload speed) is a separate, later stage.
package quality

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	"github.com/strlenstrlen/netdiag/internal/config"
	"github.com/strlenstrlen/netdiag/internal/probe"
)

// Target is a host to sample and how to reach it.
type Target struct {
	Addr   string `json:"addr"`   // IP for ICMP, host:port for TCP
	Method string `json:"method"` // "icmp" or "tcp"
}

// Plan is what stage 1 learned that stage 2 needs: which targets answer and
// by which method, and which DNS servers are configured.
type Plan struct {
	Router     *Target  `json:"router,omitempty"`
	Internet   []Target `json:"internet"`
	DNSServers []string `json:"dns_servers"`
	IPv6       bool     `json:"ipv6"`
}

type Stats struct {
	Sent             int     `json:"sent"`
	Received         int     `json:"received"`
	LossPct          float64 `json:"loss_pct"`
	P50Ms            float64 `json:"p50_ms"`
	P95Ms            float64 `json:"p95_ms"`
	MaxMs            float64 `json:"max_ms"`
	JitterMs         float64 `json:"jitter_ms"`
	SpikeThresholdMs float64 `json:"spike_threshold_ms"`
	Spikes           int     `json:"spikes"`
	SpikePct         float64 `json:"spike_pct"`
	// SpikeEvents counts separate episodes: consecutive spiky or lost
	// samples are one event (a single stall drains over several samples).
	SpikeEvents int `json:"spike_events"`
	// SpikePeriodMs is set when spikes recur on a regular timer, which
	// points at a scheduled cause (radio channel hopping, background
	// scans) rather than random interference.
	SpikePeriodMs float64 `json:"spike_period_ms,omitempty"`
}

type Series struct {
	Role  string           `json:"role"` // "router" or "internet"
	Probe probe.PingResult `json:"probe"`
	Stats Stats            `json:"stats"`
}

// Correlation compares when trouble happened on the router series versus
// the internet series. Because all series start together on the same
// schedule, the same sequence number means the same moment.
type Correlation struct {
	Computed bool `json:"computed"`
	// Moments (sequence numbers) where any internet series spiked or lost a packet.
	InternetEvents int `json:"internet_events"`
	// Of those, how many had a router spike or loss within one sample.
	InternetEventsAtRouter int `json:"internet_events_at_router"`
	RouterEvents           int `json:"router_events"`
	// Router spikes/losses with no internet trouble at the same moment:
	// the router was slow to answer ping, but traffic through it wasn't delayed.
	RouterOnlyEvents int `json:"router_only_events"`
}

// SharedFraction is the share of internet trouble that coincided with
// router trouble (0 when there was no internet trouble).
func (c Correlation) SharedFraction() float64 {
	if c.InternetEvents == 0 {
		return 0
	}
	return float64(c.InternetEventsAtRouter) / float64(c.InternetEvents)
}

type DNSTiming struct {
	Server    string    `json:"server"` // "system" or an IP
	Kind      string    `json:"kind"`   // "system", "configured" or "public"
	Queries   int       `json:"queries"`
	Answered  int       `json:"answered"`
	P50Ms     float64   `json:"p50_ms"`
	MaxMs     float64   `json:"max_ms"`
	SamplesMs []float64 `json:"samples_ms,omitempty"`
	ErrKinds  []string  `json:"error_kinds,omitempty"`
}

type HTTPSummary struct {
	URL    string             `json:"url"`
	Rounds []probe.HTTPTiming `json:"rounds"`
	OK     int                `json:"ok"`
	// Medians over successful rounds.
	DNSMs     float64 `json:"dns_ms"`
	ConnectMs float64 `json:"connect_ms"`
	TLSMs     float64 `json:"tls_ms"`
	ServerMs  float64 `json:"server_ms"`
	TotalMs   float64 `json:"total_ms"`
}

type FamilyCompare struct {
	V4      []probe.PingResult `json:"v4"`
	V6      []probe.PingResult `json:"v6"`
	V4P50Ms float64            `json:"v4_p50_ms"`
	V6P50Ms float64            `json:"v6_p50_ms"`
	V4OK    int                `json:"v4_ok"`
	V6OK    int                `json:"v6_ok"`
}

type Results struct {
	DurationMs    float64        `json:"duration_ms"`
	SeriesSeconds int            `json:"series_seconds"`
	Plan          Plan           `json:"plan"`
	Router        *Series        `json:"router,omitempty"`
	Internet      []Series       `json:"internet"`
	Correlation   Correlation    `json:"correlation"`
	DNS           []DNSTiming    `json:"dns"`
	HTTP          []HTTPSummary  `json:"http"`
	Family        *FamilyCompare `json:"ip_family,omitempty"`
}

// InternetStats combines the internet series: medians of each series'
// latency figures, mean loss and spike rate.
func (r Results) InternetStats() Stats {
	var s Stats
	if len(r.Internet) == 0 {
		return s
	}
	var p50, p95, jit, mx []float64
	for _, x := range r.Internet {
		p50 = append(p50, x.Stats.P50Ms)
		p95 = append(p95, x.Stats.P95Ms)
		jit = append(jit, x.Stats.JitterMs)
		mx = append(mx, x.Stats.MaxMs)
		s.Sent += x.Stats.Sent
		s.Received += x.Stats.Received
		s.LossPct += x.Stats.LossPct
		s.SpikePct += x.Stats.SpikePct
		s.Spikes += x.Stats.Spikes
		s.SpikeEvents = max(s.SpikeEvents, x.Stats.SpikeEvents)
	}
	n := float64(len(r.Internet))
	s.LossPct /= n
	s.SpikePct /= n
	s.P50Ms, s.P95Ms, s.JitterMs = probe.Median(p50), probe.Median(p95), probe.Median(jit)
	s.MaxMs = probe.Percentile(mx, 100)
	return s
}

// DNSByKind returns the timing for the system resolver and the fastest
// public resolver that answered.
func (r Results) DNSByKind() (system *DNSTiming, bestPublic *DNSTiming) {
	for i, d := range r.DNS {
		switch d.Kind {
		case "system":
			system = &r.DNS[i]
		case "public":
			if d.Answered > 0 && (bestPublic == nil || d.P50Ms < bestPublic.P50Ms) {
				bestPublic = &r.DNS[i]
			}
		}
	}
	return
}

type Options struct {
	// Progress receives short status lines; it may be nil.
	Progress func(string)
}

func Run(ctx context.Context, cfg config.Config, plan Plan, opts Options) Results {
	progress := opts.Progress
	if progress == nil {
		progress = func(string) {}
	}
	start := time.Now()
	res := Results{Plan: plan, SeriesSeconds: cfg.QualitySeconds}
	timeout := cfg.ProbeTimeout()

	// Phase A: request-style timing (a few seconds). Kept apart from the
	// latency series so its traffic doesn't disturb those measurements.
	progress("Timing DNS and web page starts…")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); res.DNS = runDNS(ctx, cfg, plan, timeout) }()
	go func() { defer wg.Done(); res.HTTP = runHTTP(ctx, cfg, timeout) }()
	if plan.IPv6 {
		wg.Add(1)
		go func() { defer wg.Done(); res.Family = runFamily(ctx, cfg, timeout) }()
	}
	wg.Wait()

	// Phase B: the latency series, router and internet sampled together.
	n := cfg.QualitySamples()
	interval := cfg.QualityInterval()
	sample := func(t Target) probe.PingResult {
		if t.Method == "tcp" {
			return probe.TCPPing(ctx, t.Addr, n, interval, timeout)
		}
		return probe.Ping(ctx, t.Addr, n, interval, timeout)
	}
	stop := make(chan struct{})
	go countdown(progress, time.Duration(cfg.QualitySeconds)*time.Second, stop)
	var router probe.PingResult
	internet := make([]probe.PingResult, len(plan.Internet))
	if plan.Router != nil {
		wg.Add(1)
		go func() { defer wg.Done(); router = sample(*plan.Router) }()
	}
	for i, t := range plan.Internet {
		wg.Add(1)
		go func() { defer wg.Done(); internet[i] = sample(t) }()
	}
	wg.Wait()
	close(stop)

	if plan.Router != nil {
		res.Router = &Series{Role: "router", Probe: router, Stats: Summarize(router)}
	}
	for _, p := range internet {
		res.Internet = append(res.Internet, Series{Role: "internet", Probe: p, Stats: Summarize(p)})
	}
	res.Correlation = Correlate(res.Router, res.Internet)
	res.DurationMs = float64(time.Since(start).Milliseconds())
	return res
}

func countdown(progress func(string), d time.Duration, stop <-chan struct{}) {
	end := time.Now().Add(d)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		left := time.Until(end).Round(time.Second)
		if left < 0 {
			left = 0
		}
		progress(fmt.Sprintf("Measuring latency and stability… %ds left", int(left.Seconds())))
		select {
		case <-stop:
			return
		case <-t.C:
		}
	}
}

// spikeThreshold: a sample is a spike when it exceeds the median by at
// least 30 ms and by at least the median itself (so a 600 ms satellite
// link isn't flagged for ordinary variation).
func spikeThreshold(p50 float64) float64 { return p50 + max(30, p50) }

func Summarize(p probe.PingResult) Stats {
	s := Stats{
		Sent:     p.Sent,
		Received: p.Received,
		LossPct:  p.LossPct(),
		P50Ms:    probe.Median(p.RTTsMs),
		P95Ms:    probe.Percentile(p.RTTsMs, 95),
		MaxMs:    p.MaxMs(),
		JitterMs: p.JitterMs(),
	}
	s.SpikeThresholdMs = spikeThreshold(s.P50Ms)
	for _, r := range p.RTTsMs {
		if r > s.SpikeThresholdMs {
			s.Spikes++
		}
	}
	if s.Received > 0 {
		s.SpikePct = 100 * float64(s.Spikes) / float64(s.Received)
	}
	starts := eventStarts(p, s.SpikeThresholdMs)
	s.SpikeEvents = len(starts)
	s.SpikePeriodMs = spikePeriod(starts)
	return s
}

// eventStarts merges consecutive spiky or lost samples into one event and
// returns each event's start time.
func eventStarts(p probe.PingResult, threshold float64) []float64 {
	var starts []float64
	prev := false
	for _, x := range p.Samples {
		ev := x.Lost || x.RTTMs > threshold
		if ev && !prev {
			starts = append(starts, x.AtMs)
		}
		prev = ev
	}
	return starts
}

// spikePeriod returns the mean spacing between events when there are at
// least six and the spacing is nearly even (coefficient of variation
// ≤ 0.35). Random events have a coefficient of variation near 1.
func spikePeriod(starts []float64) float64 {
	if len(starts) < 6 {
		return 0
	}
	var gaps []float64
	var sum float64
	for i := 1; i < len(starts); i++ {
		g := starts[i] - starts[i-1]
		gaps = append(gaps, g)
		sum += g
	}
	mean := sum / float64(len(gaps))
	var ss float64
	for _, g := range gaps {
		ss += (g - mean) * (g - mean)
	}
	if mean <= 0 || math.Sqrt(ss/float64(len(gaps)))/mean > 0.35 {
		return 0
	}
	return math.Round(mean)
}

// events returns the sequence numbers where a series spiked or lost a packet.
func events(s Series) map[int]bool {
	m := map[int]bool{}
	for _, x := range s.Probe.Samples {
		if x.Lost || x.RTTMs > s.Stats.SpikeThresholdMs {
			m[x.Seq] = true
		}
	}
	return m
}

func Correlate(router *Series, internet []Series) Correlation {
	var c Correlation
	if router == nil || len(internet) == 0 {
		return c
	}
	c.Computed = true
	near := func(m map[int]bool, seq int) bool { return m[seq-1] || m[seq] || m[seq+1] }

	rEv := events(*router)
	inet := map[int]bool{}
	for _, s := range internet {
		for seq := range events(s) {
			inet[seq] = true
		}
	}
	c.InternetEvents = len(inet)
	for seq := range inet {
		if near(rEv, seq) {
			c.InternetEventsAtRouter++
		}
	}
	c.RouterEvents = len(rEv)
	for seq := range rEv {
		if !near(inet, seq) {
			c.RouterOnlyEvents++
		}
	}
	return c
}

// ---- DNS ----

func runDNS(ctx context.Context, cfg config.Config, plan Plan, timeout time.Duration) []DNSTiming {
	type job struct{ server, kind string }
	jobs := []job{{"system", "system"}}
	for _, s := range plan.DNSServers {
		jobs = append(jobs, job{s, "configured"})
	}
	for _, s := range cfg.PublicDNS {
		jobs = append(jobs, job{s, "public"})
	}
	out := make([]DNSTiming, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = timeResolver(ctx, j.server, j.kind, cfg, timeout)
		}()
	}
	wg.Wait()
	return out
}

// timeResolver looks up names that can't be cached anywhere (random
// labels), sequentially, so each sample measures a full recursive lookup:
// the delay a browser pays the first time it visits a site.
func timeResolver(ctx context.Context, server, kind string, cfg config.Config, timeout time.Duration) DNSTiming {
	t := DNSTiming{Server: server, Kind: kind}
	seenErr := map[string]bool{}
	for i := range cfg.ColdDNSQueries {
		if len(cfg.ColdDNSDomains) == 0 {
			break
		}
		name := randomLabel() + "." + cfg.ColdDNSDomains[i%len(cfg.ColdDNSDomains)]
		var r probe.DNSResult
		if server == "system" {
			r = probe.LookupSystem(ctx, name, timeout)
		} else {
			r = probe.LookupVia(ctx, server, name, timeout)
		}
		t.Queries++
		// "No such host" is the expected answer for a random name.
		if r.OK || r.NotFound {
			t.Answered++
			t.SamplesMs = append(t.SamplesMs, r.RTTMs)
		} else if !seenErr[r.ErrKind] {
			seenErr[r.ErrKind] = true
			t.ErrKinds = append(t.ErrKinds, r.ErrKind)
		}
	}
	t.P50Ms = probe.Median(t.SamplesMs)
	t.MaxMs = probe.Percentile(t.SamplesMs, 100)
	return t
}

func randomLabel() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "netdiag-" + hex.EncodeToString(b)
}

// ---- HTTP ----

func runHTTP(ctx context.Context, cfg config.Config, timeout time.Duration) []HTTPSummary {
	out := make([]HTTPSummary, len(cfg.TimingURLs))
	var wg sync.WaitGroup
	for i, u := range cfg.TimingURLs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := HTTPSummary{URL: u}
			for range max(1, cfg.TimingRounds) {
				s.Rounds = append(s.Rounds, probe.HTTPTime(ctx, u, timeout))
			}
			var dns, conn, tls, srv, total []float64
			for _, r := range s.Rounds {
				if r.OK {
					s.OK++
					dns, conn, tls = append(dns, r.DNSMs), append(conn, r.ConnectMs), append(tls, r.TLSMs)
					srv, total = append(srv, r.ServerMs), append(total, r.TotalMs)
				}
			}
			s.DNSMs, s.ConnectMs, s.TLSMs = probe.Median(dns), probe.Median(conn), probe.Median(tls)
			s.ServerMs, s.TotalMs = probe.Median(srv), probe.Median(total)
			out[i] = s
		}()
	}
	wg.Wait()
	return out
}

// ---- IPv4 vs IPv6 ----

// runFamily times TCP handshakes to the same providers over each family
// (1.1.1.1 vs 2606:4700:4700::1111, and so on).
func runFamily(ctx context.Context, cfg config.Config, timeout time.Duration) *FamilyCompare {
	f := &FamilyCompare{}
	pairs := min(len(cfg.TCPTargets), len(cfg.TCPTargets6))
	f.V4 = make([]probe.PingResult, pairs)
	f.V6 = make([]probe.PingResult, pairs)
	var wg sync.WaitGroup
	for i := range pairs {
		wg.Add(2)
		go func() {
			defer wg.Done()
			f.V4[i] = probe.TCPPing(ctx, cfg.TCPTargets[i], 5, 200*time.Millisecond, timeout)
		}()
		go func() {
			defer wg.Done()
			f.V6[i] = probe.TCPPing(ctx, cfg.TCPTargets6[i], 5, 200*time.Millisecond, timeout)
		}()
	}
	wg.Wait()
	var v4, v6 []float64
	for i := range pairs {
		v4 = append(v4, f.V4[i].RTTsMs...)
		v6 = append(v6, f.V6[i].RTTsMs...)
		f.V4OK += f.V4[i].Received
		f.V6OK += f.V6[i].Received
	}
	f.V4P50Ms, f.V6P50Ms = probe.Median(v4), probe.Median(v6)
	return f
}

// HostOnly strips a port from "host:port" or "[v6]:port".
func HostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
