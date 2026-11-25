package watch

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/strlenstrlen/netdiag/internal/probe"
	"github.com/strlenstrlen/netdiag/internal/snapshot"
	"github.com/strlenstrlen/netdiag/internal/target"
)

type Options struct {
	Interval time.Duration // between probe rounds (default 1 s)
	Duration time.Duration // 0 = until ctx is cancelled
	Internet []string      // internet hosts to ping (default 1.1.1.1, 8.8.8.8)
	// OnTick is called after every round with the running summary.
	OnTick  func(t Tick, s Summary)
	OnEvent func(e Event, ended bool)
}

type DNSSample struct {
	At    time.Time `json:"t"`
	OK    bool      `json:"ok"`
	Ms    float64   `json:"ms"`
	Error string    `json:"error,omitempty"`
}

type Results struct {
	Started      time.Time         `json:"started"`
	Ended        time.Time         `json:"ended"`
	IntervalMs   int               `json:"interval_ms"`
	Router       string            `json:"router,omitempty"`
	RouterMethod string            `json:"router_method,omitempty"`
	RouterNote   string            `json:"router_note,omitempty"`
	Internet     []string          `json:"internet"`
	Method       string            `json:"method"` // per internet target: icmp or tcp
	Snapshot     snapshot.Snapshot `json:"snapshot"`
	Ticks        []Tick            `json:"ticks"`
	DNS          []DNSSample       `json:"dns"`
	States       []State           `json:"states"`
	Events       []Event           `json:"events"`
	Summary      Summary           `json:"summary"`
}

type Summary struct {
	DurationSec      float64           `json:"duration_sec"`
	Ticks            int               `json:"ticks"`
	UptimePct        float64           `json:"uptime_pct"`
	Outages          int               `json:"outages"`
	OutageSec        float64           `json:"outage_sec"`
	LongestOutageSec float64           `json:"longest_outage_sec"`
	ByCause          map[string]int    `json:"outages_by_cause,omitempty"`
	LagEpisodes      int               `json:"lag_episodes"`
	DNSFailures      int               `json:"dns_failures"`
	WiFiEvents       int               `json:"wifi_events"`
	RouterLossPct    float64           `json:"router_loss_pct"`
	InetLossPct      float64           `json:"internet_loss_pct"`
	InetP50Ms        float64           `json:"internet_p50_ms"`
	InetP95Ms        float64           `json:"internet_p95_ms"`
	RouterP50Ms      float64           `json:"router_p50_ms"`
	Conclusion       target.Conclusion `json:"conclusion"`
}

func Run(ctx context.Context, o Options) Results {
	if o.Interval <= 0 {
		o.Interval = time.Second
	}
	if len(o.Internet) == 0 {
		o.Internet = []string{"1.1.1.1", "8.8.8.8"}
	}
	if o.Duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.Duration)
		defer cancel()
	}
	snap := snapshot.Collect(ctx)
	r := Results{Started: time.Now(), IntervalMs: int(o.Interval.Milliseconds()), Internet: o.Internet, Snapshot: snap, Method: "icmp"}

	// Pick how to probe each target from what actually answers. Some
	// networks drop ping replies (common in clouds and offices) and some
	// OSes refuse unprivileged ping; probing those by ping would look like
	// a permanent outage.
	var routerT *probeTarget
	if snap.DefaultRoute != nil && net.ParseIP(snap.DefaultRoute.Gateway) != nil {
		gw := snap.DefaultRoute.Gateway
		if t, ok := pickMethod(ctx, gw, []string{"53", "80", "443"}); ok {
			routerT = &t
			r.Router, r.RouterMethod = gw, t.method
		} else {
			r.RouterNote = "The router (" + gw + ") doesn't answer ping or TCP, so outages can't be split into local and upstream"
		}
	}
	inetT := make([]probeTarget, len(o.Internet))
	var methods []string
	for i, h := range o.Internet {
		t, ok := pickMethod(ctx, h, []string{"443"})
		if !ok { // nothing answers yet (maybe offline right now): keep trying both
			t = probeTarget{addr: h, method: "icmp", port: "443"}
		}
		inetT[i] = t
		methods = append(methods, t.method)
	}
	r.Method = strings.Join(methods, ",")

	var mu sync.Mutex
	det := &Detector{OnEvent: o.OnEvent, NoRouter: routerT == nil}
	timeout := min(o.Interval*9/10, 2*time.Second)
	one := func(t probeTarget) *float64 {
		var p probe.PingResult
		if t.method == "tcp" {
			p = probe.TCPPing(ctx, net.JoinHostPort(t.addr, t.port), 1, 0, timeout)
		} else {
			p = probe.Ping(ctx, t.addr, 1, 0, timeout)
		}
		if p.OK() {
			v := p.RTTsMs[0]
			return &v
		}
		return nil
	}

	// Configuration and DNS run on their own slower schedules.
	var bg sync.WaitGroup
	bg.Add(2)
	go func() {
		defer bg.Done()
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			st := stateOf(snapshot.Collect(ctx))
			mu.Lock()
			r.States = append(r.States, st)
			det.State(st)
			mu.Unlock()
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	go func() {
		defer bg.Done()
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			res := probe.LookupSystem(ctx, randomName(), 3*time.Second)
			if ctx.Err() != nil {
				return
			}
			ok := res.OK || res.NotFound // a random name should come back "no such name"
			mu.Lock()
			r.DNS = append(r.DNS, DNSSample{At: time.Now(), OK: ok, Ms: res.RTTMs, Error: res.ErrKind})
			det.DNS(time.Now(), ok, res.ErrKind)
			mu.Unlock()
		}
	}()

	tk := time.NewTicker(o.Interval)
	defer tk.Stop()
	for ctx.Err() == nil {
		at := time.Now()
		var tick Tick
		tick.At = at
		var wg sync.WaitGroup
		if routerT != nil {
			wg.Add(1)
			go func() { defer wg.Done(); tick.Router = one(*routerT) }()
		}
		results := make([]*float64, len(o.Internet))
		for i, t := range inetT {
			wg.Add(1)
			go func() { defer wg.Done(); results[i] = one(t) }()
		}
		wg.Wait()
		if ctx.Err() != nil {
			break // don't record a round cut short by stopping
		}
		for _, v := range results {
			if v != nil && (tick.Inet == nil || *v < *tick.Inet) {
				tick.Inet = v
			}
		}
		mu.Lock()
		r.Ticks = append(r.Ticks, tick)
		det.Tick(tick)
		sum := summarize(r, det.Events)
		mu.Unlock()
		if o.OnTick != nil {
			o.OnTick(tick, sum)
		}
		select {
		case <-ctx.Done():
		case <-tk.C:
		}
	}
	bg.Wait()
	r.Ended = time.Now()
	det.Finish(r.Ended)
	r.Events = det.Events
	r.Summary = Summarize(r)
	return r
}

// Summarize computes the summary and conclusion for a finished run.
func Summarize(r Results) Summary {
	r.Summary = summarize(r, r.Events)
	r.Summary.Conclusion = Conclude(r)
	return r.Summary
}

type probeTarget struct{ addr, method, port string }

// pickMethod returns ICMP if the host answers ping, else TCP on the first
// port that answers (a refusal counts: the host is alive), else ok=false.
func pickMethod(ctx context.Context, addr string, ports []string) (probeTarget, bool) {
	if p := probe.Ping(ctx, addr, 2, 200*time.Millisecond, time.Second); p.OK() {
		return probeTarget{addr: addr, method: "icmp"}, true
	}
	for _, port := range ports {
		if probe.TCPConnect(ctx, net.JoinHostPort(addr, port), 2*time.Second).HostAlive() {
			return probeTarget{addr: addr, method: "tcp", port: port}, true
		}
	}
	return probeTarget{}, false
}

func stateOf(s snapshot.Snapshot) State {
	st := State{At: time.Now(), Interface: s.PrimaryInterface, VPN: s.VPN.Active}
	if s.DefaultRoute != nil {
		st.Gateway = s.DefaultRoute.Gateway
	}
	for _, it := range s.Interfaces {
		if it.Name == s.PrimaryInterface {
			if a := it.RoutableIPv4(); len(a) > 0 {
				st.IPv4 = a[0]
			}
		}
	}
	if w := s.WiFi; w != nil {
		st.WiFiKnown = true
		st.WiFiOn = w.Associated
		st.RSSI, st.Channel = w.RSSI, w.Channel
	}
	return st
}

func randomName() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "netdiag-" + hex.EncodeToString(b) + ".google.com"
}

func summarize(r Results, events []Event) Summary {
	s := Summary{Ticks: len(r.Ticks), ByCause: map[string]int{}}
	if len(r.Ticks) > 0 {
		s.DurationSec = math.Round(r.Ticks[len(r.Ticks)-1].At.Sub(r.Ticks[0].At).Seconds()) + float64(r.IntervalMs)/1000
	}
	var inet, router []float64
	inetLost, routerLost, routerN := 0, 0, 0
	for _, t := range r.Ticks {
		if t.Inet != nil {
			inet = append(inet, *t.Inet)
		} else {
			inetLost++
		}
		if r.Router != "" {
			routerN++
			if t.Router != nil {
				router = append(router, *t.Router)
			} else {
				routerLost++
			}
		}
	}
	if s.Ticks > 0 {
		s.InetLossPct = round1(100 * float64(inetLost) / float64(s.Ticks))
	}
	if routerN > 0 {
		s.RouterLossPct = round1(100 * float64(routerLost) / float64(routerN))
	}
	s.InetP50Ms, s.InetP95Ms = round1(probe.Percentile(inet, 50)), round1(probe.Percentile(inet, 95))
	s.RouterP50Ms = round1(probe.Percentile(router, 50))
	for _, e := range events {
		switch e.Kind {
		case "outage":
			s.Outages++
			d := e.Duration().Seconds()
			s.OutageSec += d
			s.LongestOutageSec = math.Max(s.LongestOutageSec, d)
			s.ByCause[e.Cause]++
		case "lag":
			s.LagEpisodes++
		case "dns":
			s.DNSFailures++
		case "wifi", "signal":
			s.WiFiEvents++
		}
	}
	s.OutageSec = math.Round(s.OutageSec)
	if s.DurationSec > 0 {
		s.UptimePct = round1(100 * math.Max(0, 1-s.OutageSec/s.DurationSec))
	}
	return s
}

// Conclude explains the run: whether it dropped, and where.
func Conclude(r Results) target.Conclusion {
	s := r.Summary
	dur := human(time.Duration(s.DurationSec * float64(time.Second)))
	var c target.Conclusion
	ev := []string{}
	if s.Outages > 0 {
		ev = append(ev, fmt.Sprintf("%d %s, %s offline in total (longest %s); %.1f%% uptime",
			s.Outages, plural(s.Outages, "outage", "outages"), human(time.Duration(s.OutageSec)*time.Second),
			human(time.Duration(s.LongestOutageSec)*time.Second), s.UptimePct))
	}
	causes := []string{}
	for _, k := range []string{CauseWiFi, CauseLocal, CauseUpstream} {
		if n := s.ByCause[k]; n > 0 {
			causes = append(causes, fmt.Sprintf("%d %s", n, map[string]string{
				CauseWiFi: "during a Wi-Fi disconnect or change", CauseLocal: "with the router unreachable too", CauseUpstream: "with the router still answering"}[k]))
		}
	}
	if len(causes) > 0 {
		ev = append(ev, "Of those: "+strings.Join(causes, "; "))
	}
	if s.WiFiEvents > 0 {
		var ws []string
		for _, e := range r.Events {
			if e.Kind == "wifi" || e.Kind == "signal" {
				ws = append(ws, e.Start.Format("15:04:05")+" "+e.Title)
			}
		}
		ev = append(ev, "Wi-Fi events: "+strings.Join(firstN(ws, 4), "; "))
	}
	if s.LagEpisodes > 0 {
		ev = append(ev, fmt.Sprintf("%d %s of high latency", s.LagEpisodes, plural(s.LagEpisodes, "episode", "episodes")))
	}
	if s.DNSFailures > 0 {
		ev = append(ev, fmt.Sprintf("%d DNS %s failed while the connection was up", s.DNSFailures, plural(s.DNSFailures, "lookup", "lookups")))
	}

	local := s.ByCause[CauseWiFi] + s.ByCause[CauseLocal]
	up := s.ByCause[CauseUpstream]
	var localSec, upSec float64
	for _, e := range r.Events {
		if e.Kind == "outage" {
			if e.Cause == CauseUpstream {
				upSec += e.Duration().Seconds()
			} else {
				localSec += e.Duration().Seconds()
			}
		}
	}
	lagLocal, lagUp := 0, 0
	for _, e := range r.Events {
		if e.Kind == "lag" {
			if e.Cause == CauseUpstream {
				lagUp++
			} else {
				lagLocal++
			}
		}
	}
	localSteps := []string{
		"Move closer to the router or use a wired connection, and see if the drops stop",
		"Restart the router; if drops continue, check for firmware updates or interference",
	}
	upSteps := []string{
		"Check the modem's status lights or event log at the time of the drops",
		"Restart the modem; if drops continue, send this report to your internet provider with the times listed",
	}
	if r.RouterNote != "" && s.Outages > 0 {
		ev = append(ev, r.RouterNote)
	}
	switch {
	case s.Outages > 0 && local == 0 && up == 0:
		c = target.Conclusion{Status: "fail", Owner: "Wi-Fi, router or internet provider",
			Headline: fmt.Sprintf("The connection dropped %d %s in %s", s.Outages, plural(s.Outages, "time", "times"), dur),
			Evidence: ev, NextSteps: append(append([]string{}, localSteps[0]), upSteps...)}
	case local > 0 && up > 0:
		c = target.Conclusion{Status: "fail",
			Headline: fmt.Sprintf("The connection dropped %d times in %s: %d on your Wi-Fi or local network, %d beyond your router", s.Outages, dur, local, up),
			Evidence: ev}
		if localSec >= upSec {
			c.Owner, c.NextSteps = "Wi-Fi / local network first, then your internet provider", append(localSteps, upSteps...)
		} else {
			c.Owner, c.NextSteps = "Internet provider (ISP) first, then the Wi-Fi", append(upSteps, localSteps...)
		}
	case s.Outages > 0 && local > 0:
		c = target.Conclusion{Status: "fail", Owner: "Wi-Fi / local network",
			Headline: fmt.Sprintf("The connection dropped %d %s in %s, on your Wi-Fi or local network", s.Outages, plural(s.Outages, "time", "times"), dur),
			Evidence: ev, NextSteps: localSteps}
	case s.Outages > 0:
		c = target.Conclusion{Status: "fail", Owner: "Internet provider (ISP)",
			Headline: fmt.Sprintf("The connection dropped %d %s in %s, beyond your router", s.Outages, plural(s.Outages, "time", "times"), dur),
			Evidence: ev, NextSteps: upSteps}
	case s.LagEpisodes > 0:
		c = target.Conclusion{Status: "warn", Evidence: ev,
			Headline: fmt.Sprintf("No drops in %s, but %d %s of high latency", dur, s.LagEpisodes, plural(s.LagEpisodes, "episode", "episodes"))}
		if lagLocal >= lagUp {
			c.Owner, c.NextSteps = "Wi-Fi / local network", localSteps
		} else {
			c.Owner, c.NextSteps = "Internet provider (ISP)", upSteps
		}
	case s.DNSFailures > 0:
		c = target.Conclusion{Status: "warn", Owner: "DNS provider (router or ISP)", Evidence: ev,
			Headline:  fmt.Sprintf("No drops in %s, but DNS failed %d %s", dur, s.DNSFailures, plural(s.DNSFailures, "time", "times")),
			NextSteps: []string{"Try public DNS (1.1.1.1, 8.8.8.8) and see if pages stop failing to load"}}
	default:
		c = target.Conclusion{Status: "ok",
			Headline:  fmt.Sprintf("No drops or slowdowns in %s", dur),
			Evidence:  append(ev, fmt.Sprintf("Internet %.0f ms typical (95%% under %.0f ms), %.1f%% of probes lost", s.InetP50Ms, s.InetP95Ms, s.InetLossPct)),
			NextSteps: []string{"If drops happen at certain times, run `netdiag watch --for 2h` across those times"}}
	}
	if s.WiFiEvents > 0 && c.Status == "ok" {
		c.Status = "warn"
		c.Owner = "Wi-Fi / local network"
		c.Headline = fmt.Sprintf("No drops in %s, but the Wi-Fi connection changed %d %s", dur, s.WiFiEvents, plural(s.WiFiEvents, "time", "times"))
	}
	return c
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func firstN(xs []string, n int) []string {
	if len(xs) > n {
		return append(xs[:n:n], fmt.Sprintf("and %d more", len(xs)-n))
	}
	return xs
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }
