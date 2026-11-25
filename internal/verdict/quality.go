package verdict

// Stage-2 rules: lag, loss, jitter, DNS speed, page-start time, IPv6 speed.
//
// The key technique is comparing the router series with the internet
// series sample by sample:
//   - trouble on both at the same moments  → it happens on the local network
//   - trouble only on the internet series  → it happens beyond the router
//   - trouble only on the router series    → the router answers ping at low
//     priority; traffic through it is fine (a common false alarm)

import (
	"fmt"
	"strings"

	"github.com/strlenstrlen/netdiag/internal/probe"
	"github.com/strlenstrlen/netdiag/internal/quality"
)

const (
	lossWarnPct    = 2.0  // video calls degrade noticeably above ~1–2%
	spikeWarnPct   = 5.0  // share of samples that spiked
	minSpikeEvents = 3    // separate episodes in one series before it counts as a pattern
	jitterWarnMs   = 30.0 // common guidance for real-time voice/video
)

func qualityFindings(f facts) []Finding {
	q := f.r.Quality
	if q == nil {
		return nil
	}
	var out []Finding
	add := func(x Finding) { out = append(out, x) }

	in := q.InternetStats()
	hasInet := in.Received > 0
	var rs *quality.Stats
	if q.Router != nil && q.Router.Stats.Received > 0 {
		rs = &q.Router.Stats
	}
	c := q.Correlation

	wifiLine := ""
	if w := f.wifi; w != nil && w.SignalKnown && w.Associated {
		strength := "strong"
		if isWeakSignal(*w) {
			strength = "weak"
		}
		wifiLine = fmt.Sprintf("Wi-Fi signal is %s (%d dBm, SNR %d dB)", strength, w.RSSI, w.SNR())
	}
	withWiFi := func(ev []string) []string {
		if wifiLine != "" {
			ev = append(ev, wifiLine)
		}
		return ev
	}
	localSteps := func() []string {
		steps := []string{}
		if w := f.wifi; w != nil && w.SignalKnown && !isWeakSignal(*w) {
			steps = append(steps, "The signal is strong, so look for interference, a crowded channel, or another device saturating the network")
		} else if f.wifi != nil {
			steps = append(steps, "Move closer to the router, or use the 5 GHz or 6 GHz network")
		}
		return append(steps,
			"Pause large downloads, uploads, backups or streams on other devices, then run netdiag again",
			"Compare with a wired connection: if the problem disappears, the Wi-Fi is the cause",
			"Restart the router",
		)
	}

	// ---- Packet loss ----
	switch {
	case rs != nil && rs.LossPct >= lossWarnPct && hasInet && in.LossPct >= lossWarnPct/2:
		add(Finding{
			ID: "local-loss", Severity: SevWarn, Impact: 90, Confidence: "high", Owner: OwnerWiFi,
			Title: "Packet loss on your local network",
			Evidence: withWiFi([]string{
				fmt.Sprintf("%.1f%% of packets to the router were lost (%d of %d)", rs.LossPct, rs.Sent-rs.Received, rs.Sent),
				fmt.Sprintf("Internet traffic lost %.1f%% too, so packets are dropped before they leave your network", in.LossPct),
			}),
			NextSteps: localSteps(),
		})
	case rs != nil && rs.LossPct >= lossWarnPct:
		add(Finding{
			ID: "router-ping-loss", Severity: SevInfo, Owner: OwnerRouter,
			Title:    "Your router ignores some pings, but traffic through it isn't lost",
			Evidence: []string{fmt.Sprintf("%.1f%% of pings to the router went unanswered while internet traffic lost %.1f%%; routers often answer pings at low priority", rs.LossPct, in.LossPct)},
		})
	}
	if hasInet && in.LossPct >= lossWarnPct && (rs == nil || rs.LossPct < 1) {
		ev := []string{fmt.Sprintf("%.1f%% of packets to internet hosts were lost; above 1%%, video calls stutter", in.LossPct)}
		if rs != nil {
			ev = append(ev, fmt.Sprintf("Only %.1f%% were lost to your router, so the loss happens past it: in the modem or the internet provider's network", rs.LossPct))
		}
		add(Finding{
			ID: "upstream-loss", Severity: SevWarn, Impact: 85, Confidence: confidence(rs != nil), Owner: OwnerISP,
			Title:    "Packet loss beyond your router",
			Evidence: ev,
			NextSteps: []string{
				"Restart the modem (not just the router)",
				"If it continues, report packet loss to your internet provider and send them this report",
			},
		})
	}

	// ---- Lag spikes ----
	// A pattern needs enough spiky samples AND several separate episodes:
	// one stall drains over several samples and would otherwise look like
	// a 5% spike rate on its own.
	routerSpiky := rs != nil && rs.SpikePct >= spikeWarnPct && rs.SpikeEvents >= minSpikeEvents
	inetSpiky := hasInet && in.SpikePct >= spikeWarnPct && in.SpikeEvents >= minSpikeEvents
	if !routerSpiky && !inetSpiky && hasInet && in.SpikeEvents > 0 && in.MaxMs >= 100 {
		where := "beyond your router"
		if rs != nil && c.Computed && c.SharedFraction() >= 0.5 {
			where = "on the local network"
		}
		add(Finding{
			ID: "brief-stall", Severity: SevInfo,
			Title: fmt.Sprintf("A brief stall (up to %.0f ms) happened %s, but not as a pattern", in.MaxMs, where),
			Evidence: []string{fmt.Sprintf("%d separate %s in %d seconds; occasional hiccups like this are normal",
				in.SpikeEvents, plural(in.SpikeEvents, "episode", "episodes"), q.SeriesSeconds)},
		})
	}
	switch {
	case inetSpiky && routerSpiky && c.Computed && c.SharedFraction() >= 0.5:
		ev := []string{
			fmt.Sprintf("Router replies are usually %.0f ms but jumped above %.0f ms in %.0f%% of samples (max %.0f ms)", rs.P50Ms, rs.SpikeThresholdMs, rs.SpikePct, rs.MaxMs),
			fmt.Sprintf("%d of %d internet lag spikes happened at the same moments, so the delay is added before traffic leaves your network", c.InternetEventsAtRouter, c.InternetEvents),
		}
		steps := localSteps()
		if rs.SpikePeriodMs > 0 {
			ev = append(ev, periodLine(rs.SpikePeriodMs))
			// Scheduled causes come first: they're the most likely and the easiest to test.
			periodic := []string{"Close apps that scan Wi-Fi in the background (Wi-Fi analyzers, some VPN and location tools), then run netdiag again"}
			if awdlActive(f) {
				periodic = append([]string{"This Mac's AirDrop/Continuity link (awdl0) is active, and it moves the Wi-Fi radio to other channels on a schedule, which can cause this pattern. " +
					"Turning off AirDrop and Handoff in Settings doesn't always stop it; to test it directly, run `sudo ifconfig awdl0 down`, run netdiag again, then `sudo ifconfig awdl0 up`"}, periodic...)
			}
			steps = append(periodic, steps...)
		}
		add(Finding{
			ID: "local-lag", Severity: SevWarn, Impact: 75, Confidence: "high", Owner: OwnerWiFi,
			Title:     "Lag spikes on your local network",
			Evidence:  withWiFi(ev),
			NextSteps: steps,
		})
	case inetSpiky:
		ev := []string{fmt.Sprintf("Internet replies are usually %.0f ms but spiked in %.0f%% of samples (max %.0f ms)", in.P50Ms, in.SpikePct, in.MaxMs)}
		if rs != nil && c.Computed {
			ev = append(ev, fmt.Sprintf("The router stayed steady at %.0f ms during %d of %d of those spikes, so they happen beyond it",
				rs.P50Ms, c.InternetEvents-c.InternetEventsAtRouter, c.InternetEvents))
		}
		if p := inetPeriod(q); p > 0 {
			ev = append(ev, periodLine(p))
		}
		add(Finding{
			ID: "upstream-lag", Severity: SevWarn, Impact: 70, Confidence: confidence(c.Computed), Owner: OwnerISP,
			Title:    "Lag spikes beyond your router",
			Evidence: ev,
			NextSteps: []string{
				"If someone on your network is uploading or streaming heavily, your internet link may be saturated; pause it and run netdiag again",
				"Restart the modem",
				"If it persists, report latency spikes to your internet provider",
			},
		})
	case routerSpiky:
		add(Finding{
			ID: "router-ping-slow", Severity: SevInfo, Owner: OwnerRouter,
			Title:    "Your router is sometimes slow to answer pings, but traffic through it isn't delayed",
			Evidence: []string{fmt.Sprintf("Router replies spiked in %.0f%% of samples while internet traffic stayed steady; normal for routers that answer pings at low priority", rs.SpikePct)},
		})
	}

	// ---- Jitter (when spikes don't already explain it) ----
	if hasInet && !inetSpiky && in.JitterMs >= jitterWarnMs {
		owner := OwnerISP
		if rs != nil && rs.JitterMs >= jitterWarnMs {
			owner = OwnerWiFi
		}
		add(Finding{
			ID: "jitter", Severity: SevWarn, Impact: 60, Confidence: "medium", Owner: owner,
			Title:    "Unstable latency (jitter) will affect calls and games",
			Evidence: []string{fmt.Sprintf("Latency changes by %.0f ms between consecutive packets on average; real-time audio and video need under %.0f ms", in.JitterMs, jitterWarnMs)},
		})
	}

	// ---- Base latency ----
	if rs != nil && rs.P50Ms > 30 {
		add(Finding{
			ID: "local-slow", Severity: SevWarn, Impact: 65, Confidence: "medium", Owner: OwnerWiFi,
			Title:     "Slow local network",
			Evidence:  withWiFi([]string{fmt.Sprintf("Router replies take %.0f ms typically; under 10 ms is normal", rs.P50Ms)}),
			NextSteps: localSteps(),
		})
	}
	beyond := in.P50Ms
	if rs != nil {
		beyond -= rs.P50Ms
	}
	if hasInet && beyond >= 100 {
		steps := []string{
			"On satellite or cellular internet this is expected",
			"Otherwise restart the modem, and ask your provider if it persists",
		}
		if f.r.Snapshot.VPN.Active {
			steps = append([]string{"A VPN is connected and adds latency; disconnect it and compare"}, steps...)
		}
		add(Finding{
			ID: "high-latency", Severity: SevWarn, Impact: 55, Confidence: "medium", Owner: OwnerISP,
			Title: "High latency to the internet",
			Evidence: []string{fmt.Sprintf(
				"%.0f ms round trip to major internet services (%.0f ms of it beyond your router); cable and fiber are usually under 40 ms",
				in.P50Ms, beyond)},
			NextSteps: steps,
		})
	}

	// ---- DNS speed ----
	sys, pub := q.DNSByKind()
	if sys != nil && sys.Queries > 0 {
		if missed := sys.Queries - sys.Answered; sys.Answered > 0 && float64(missed)/float64(sys.Queries) >= 0.2 {
			add(Finding{
				ID: "dns-timeouts", Severity: SevWarn, Impact: 55, Confidence: "medium", Owner: OwnerDNS,
				Title:     "Some DNS lookups get no answer",
				Evidence:  []string{fmt.Sprintf("%d of %d lookups for new sites got no answer (%s); browsers wait, then retry", missed, sys.Queries, strings.Join(sys.ErrKinds, ", "))},
				NextSteps: []string{"Try public DNS (1.1.1.1 and 8.8.8.8) in network settings"},
			})
		}
		switch {
		case sys.Answered > 0 && pub != nil && sys.P50Ms >= 150 && sys.P50Ms >= 2*pub.P50Ms:
			add(Finding{
				ID: "dns-slow", Severity: SevWarn, Impact: 50, Confidence: "high", Owner: OwnerDNS,
				Title: fmt.Sprintf("Slow DNS: each new website waits %.0f ms for its address", sys.P50Ms),
				Evidence: []string{
					fmt.Sprintf("This computer's DNS (%s) takes %.0f ms for a first lookup; public DNS %s answers in %.0f ms",
						joinOr(f.r.Snapshot.DNSServers, "system"), sys.P50Ms, pub.Server, pub.P50Ms),
					"Every site visited for the first time pays this delay, often several times per page",
				},
				NextSteps: []string{
					fmt.Sprintf("Switch DNS to %s (plus a second public server) in network settings", pub.Server),
					"Or ask whoever runs the network to fix the router's DNS",
				},
			})
		case sys.Answered > 0 && sys.P50Ms >= 300:
			ev := []string{fmt.Sprintf("First lookups take %.0f ms through this computer's DNS", sys.P50Ms)}
			if pub != nil {
				ev = append(ev, fmt.Sprintf("Public DNS is slow here too (%.0f ms at best), so the delay is in the network path", pub.P50Ms))
			}
			add(Finding{
				ID: "dns-slow-all", Severity: SevWarn, Impact: 45, Confidence: "medium", Owner: OwnerNetwork,
				Title:    "DNS lookups are slow on this network",
				Evidence: ev,
			})
		}
	}

	// ---- Page start time ----
	if ph, ok := httpPhases(q); ok && ph.total >= 1000 {
		owner := map[string]string{"DNS": OwnerDNS, "the TCP connection": OwnerNetwork, "the TLS handshake": OwnerNetwork, "the servers' responses": "The websites themselves"}[ph.dominant]
		add(Finding{
			ID: "slow-page-start", Severity: SevWarn, Impact: 45, Confidence: "medium", Owner: owner,
			Title: "Websites are slow to start loading",
			Evidence: []string{
				fmt.Sprintf("Median %.0f ms before a page's first byte arrives (%s)", ph.total, ph.breakdown()),
				"Most of the delay is in " + ph.dominant,
			},
		})
	}

	// ---- IPv6 vs IPv4 ----
	if fam := q.Family; fam != nil && fam.V4OK > 0 && fam.V6OK > 0 &&
		fam.V6P50Ms > fam.V4P50Ms+50 && fam.V6P50Ms > 1.5*fam.V4P50Ms {
		add(Finding{
			ID: "ipv6-slow", Severity: SevWarn, Impact: 40, Confidence: "medium", Owner: OwnerRouter,
			Title: "IPv6 is noticeably slower than IPv4",
			Evidence: []string{
				fmt.Sprintf("Connections take %.0f ms over IPv6 vs %.0f ms over IPv4 to the same providers", fam.V6P50Ms, fam.V4P50Ms),
				"Apps prefer IPv6, so they get the slower path",
			},
			NextSteps: []string{"Restart the router; if it persists, ask the network owner or provider about their IPv6 routing"},
		})
	}
	return out
}

func periodLine(ms float64) string {
	return fmt.Sprintf("The spikes repeat about every %.1f seconds: something running on a timer, not random interference", ms/1000)
}

// inetPeriod returns a spike period shared by the internet series, if any.
func inetPeriod(q *quality.Results) float64 {
	for _, s := range q.Internet {
		if s.Stats.SpikePeriodMs > 0 {
			return s.Stats.SpikePeriodMs
		}
	}
	return 0
}

// awdlActive: Apple Wireless Direct Link (AirDrop, Handoff, Sidecar,
// AirPlay to Mac) is up. While it runs, the Wi-Fi radio leaves the joined
// network's channel at regular intervals.
func awdlActive(f facts) bool {
	if f.r.Snapshot.OS != "darwin" {
		return false
	}
	for _, it := range f.r.Snapshot.Interfaces {
		if it.Name == "awdl0" && it.Up && it.Running {
			return true
		}
	}
	return false
}

type phases struct {
	dns, connect, tls, server, total float64
	dominant                         string
}

func (p phases) breakdown() string {
	return fmt.Sprintf("DNS %.0f · connect %.0f · TLS %.0f · server %.0f ms", p.dns, p.connect, p.tls, p.server)
}

// httpPhases takes medians across sites that loaded. Needs at least two.
func httpPhases(q *quality.Results) (phases, bool) {
	var dns, conn, tls, srv, total []float64
	for _, h := range q.HTTP {
		if h.OK > 0 {
			dns, conn, tls = append(dns, h.DNSMs), append(conn, h.ConnectMs), append(tls, h.TLSMs)
			srv, total = append(srv, h.ServerMs), append(total, h.TotalMs)
		}
	}
	if len(total) < 2 {
		return phases{}, false
	}
	med := probe.Median
	p := phases{dns: med(dns), connect: med(conn), tls: med(tls), server: med(srv), total: med(total)}
	best := -1.0
	for _, ph := range []struct {
		name string
		v    float64
	}{{"DNS", p.dns}, {"the TCP connection", p.connect}, {"the TLS handshake", p.tls}, {"the servers' responses", p.server}} {
		if ph.v > best {
			p.dominant, best = ph.name, ph.v
		}
	}
	return p, true
}

func qualityChecks(f facts, findings []Finding) []Check {
	r := f.r
	q := r.Quality
	if q == nil {
		if r.QualitySkipped != "" {
			return []Check{{Stage: StageResponsiveness, Name: "Responsiveness", Status: CheckSkip, Detail: "skipped: " + r.QualitySkipped}}
		}
		return nil
	}
	warned := map[string]bool{}
	for _, x := range findings {
		if x.Severity == SevWarn {
			warned[x.ID] = true
		}
	}
	status := func(ids ...string) CheckStatus {
		for _, id := range ids {
			if warned[id] {
				return CheckWarn
			}
		}
		return CheckPass
	}
	var cs []Check
	add := func(name string, st CheckStatus, detail string) {
		cs = append(cs, Check{Stage: StageResponsiveness, Name: name, Status: st, Detail: detail})
	}
	series := func(s quality.Stats, method string) string {
		d := fmt.Sprintf("%.0f ms typical · %.0f ms p95 · jitter %.0f ms · %.1f%% loss", s.P50Ms, s.P95Ms, s.JitterMs, s.LossPct)
		if method == "tcp" {
			d += " · via TCP"
		}
		return d
	}

	if q.Router != nil && q.Router.Stats.Received > 0 {
		add("Local network", status("local-loss", "local-lag", "local-slow"), series(q.Router.Stats, q.Router.Probe.Method))
	} else {
		add("Local network", CheckSkip, "router couldn't be measured")
	}

	if in := q.InternetStats(); in.Received > 0 {
		method := ""
		if len(q.Internet) > 0 {
			method = q.Internet[0].Probe.Method
		}
		st, d := status("upstream-loss", "upstream-lag", "jitter", "high-latency"), series(in, method)
		// Local trouble shows up in internet traffic too; say where it comes from.
		if st == CheckPass && (warned["local-lag"] || warned["local-loss"]) &&
			(in.SpikePct >= spikeWarnPct || in.LossPct >= lossWarnPct/2) {
			st, d = CheckWarn, d+" · caused by the local network"
		}
		add("Internet latency", st, d)
	} else {
		add("Internet latency", CheckSkip, "no internet host could be measured")
	}

	sys, pub := q.DNSByKind()
	switch {
	case sys == nil || sys.Queries == 0:
		add("DNS speed", CheckSkip, "not measured")
	case sys.Answered == 0:
		add("DNS speed", CheckFail, "no answers to first-time lookups")
	default:
		d := fmt.Sprintf("first lookups %.0f ms", sys.P50Ms)
		if pub != nil {
			d += fmt.Sprintf(" · fastest public DNS %.0f ms (%s)", pub.P50Ms, pub.Server)
		}
		add("DNS speed", status("dns-slow", "dns-slow-all", "dns-timeouts"), d)
	}

	if ph, ok := httpPhases(q); ok {
		add("Page start time", status("slow-page-start"), fmt.Sprintf("%.0f ms to first byte · %s", ph.total, ph.breakdown()))
	} else {
		add("Page start time", CheckSkip, "too few test sites loaded")
	}

	if fam := q.Family; fam != nil {
		add("IPv4 vs IPv6", status("ipv6-slow"), fmt.Sprintf("IPv4 %.0f ms · IPv6 %.0f ms", fam.V4P50Ms, fam.V6P50Ms))
	}
	return cs
}
