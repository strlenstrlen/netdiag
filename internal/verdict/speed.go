package verdict

// Stage-3 rules: throughput against the plan (if given) or usable minimums,
// whether Wi-Fi rather than the internet line is the bottleneck, and
// bufferbloat: how far latency rises while the link is busy, and whether the
// queue that causes it sits on the local network or at the modem/ISP.

import (
	"fmt"
	"strings"

	"github.com/strlenstrlen/netdiag/internal/speed"
)

const (
	minDownMbps = 10.0 // below this, HD video and large downloads struggle
	minUpMbps   = 3.0  // below this, video calls and cloud backups struggle
	planShare   = 0.5  // warn below half the advertised plan speed
	// Usable TCP throughput over Wi-Fi is roughly half to two-thirds of the
	// link rate, so a result above this share of it means Wi-Fi is the limit.
	wifiLimitShare = 0.45
	bloatWarnMs    = 60.0
)

// BloatGrade grades the rise in latency under load, using the scale most
// public bufferbloat tests use.
func BloatGrade(riseMs float64) string {
	switch {
	case riseMs < 5:
		return "A+"
	case riseMs < 30:
		return "A"
	case riseMs < 60:
		return "B"
	case riseMs < 200:
		return "C"
	case riseMs < 400:
		return "D"
	}
	return "F"
}

func speedFindings(f facts) []Finding {
	s := f.r.Speed
	if s == nil {
		return nil
	}
	var out []Finding
	add := func(x Finding) { out = append(out, x) }

	down, up := s.Best(speed.Download), s.Best(speed.Upload)
	w := f.wifi
	wifiLimited := func(t *speed.Transfer) bool {
		return t != nil && w != nil && w.Associated && w.TxRateMbps > 0 &&
			f.primaryIface != nil && f.primaryIface.Name == w.Interface &&
			t.Mbps >= wifiLimitShare*w.TxRateMbps
	}
	wifiLine := func() string {
		return fmt.Sprintf("The Wi-Fi link runs at %.0f Mbps; over Wi-Fi, roughly half to two-thirds of that is usable", w.TxRateMbps)
	}

	for _, d := range []struct {
		dir     string
		t       *speed.Transfer
		plan    float64
		minimum float64
		why     string
		impact  int
	}{
		{speed.Download, down, s.Plan.PlanDownMbps, minDownMbps, "streaming, downloads and page loads", 70},
		{speed.Upload, up, s.Plan.PlanUpMbps, minUpMbps, "video calls, sending files and cloud backups", 65},
	} {
		if d.t == nil {
			add(Finding{ID: "speed-unavailable-" + d.dir, Severity: SevInfo,
				Title:    fmt.Sprintf("The %s speed test couldn't run", d.dir),
				Evidence: []string{transferErrors(s, d.dir)}})
			continue
		}
		ev := []string{providerLine(s, d.dir)}
		owner, steps := OwnerISP, []string{
			"Restart the modem and router, then test again",
			"If it stays low, contact your internet provider with this report",
		}
		if wifiLimited(d.t) {
			ev = append(ev, wifiLine())
			owner = OwnerWiFi
			steps = []string{
				"Test with a wired connection to see the line's full speed",
				"Move closer to the router, or use the 5 GHz or 6 GHz network",
			}
		}
		switch {
		case d.plan > 0 && d.t.Mbps < planShare*d.plan:
			add(Finding{
				ID: "slow-" + d.dir + "-plan", Severity: SevWarn, Impact: d.impact + 10, Confidence: "medium", Owner: owner,
				Title:     fmt.Sprintf("%s speed is %.0f%% of your plan", strings.ToUpper(d.dir[:1])+d.dir[1:], 100*d.t.Mbps/d.plan),
				Evidence:  append([]string{fmt.Sprintf("Measured %.0f Mbps; the plan is %.0f Mbps", d.t.Mbps, d.plan)}, ev...),
				NextSteps: steps,
			})
		case d.plan == 0 && d.t.Mbps < d.minimum:
			add(Finding{
				ID: "slow-" + d.dir, Severity: SevWarn, Impact: d.impact, Confidence: "medium", Owner: owner,
				Title:     fmt.Sprintf("Slow %s speed (%.1f Mbps)", d.dir, d.t.Mbps),
				Evidence:  append(ev, fmt.Sprintf("Under %.0f Mbps makes %s slow", d.minimum, d.why)),
				NextSteps: steps,
			})
		}
	}
	if wifiLimited(down) && !hasID(out, "slow-download") && !hasID(out, "slow-download-plan") {
		add(Finding{ID: "wifi-caps-speed", Severity: SevInfo, Owner: OwnerWiFi,
			Title: fmt.Sprintf("Wi-Fi likely limits this computer's speed (%.0f Mbps)", down.Mbps),
			Evidence: []string{wifiLine(),
				"A wired test would show whether the internet line itself is faster"}})
	}

	// Providers disagreeing a lot usually means one congested route, not the line.
	for _, dir := range []string{speed.Download, speed.Upload} {
		var lo, hi *speed.Transfer
		for i, t := range s.Transfers {
			if t.Direction == dir && t.OK {
				if lo == nil || t.Mbps < lo.Mbps {
					lo = &s.Transfers[i]
				}
				if hi == nil || t.Mbps > hi.Mbps {
					hi = &s.Transfers[i]
				}
			}
		}
		if lo != nil && hi != nil && lo != hi && hi.Mbps >= 2*lo.Mbps {
			add(Finding{ID: "speed-providers-differ-" + dir, Severity: SevInfo,
				Title:    fmt.Sprintf("%s results differ by provider; the faster one reflects your line", strings.ToUpper(dir[:1])+dir[1:]),
				Evidence: []string{fmt.Sprintf("%s %.0f Mbps vs %s %.0f Mbps; the slower route or server is the bottleneck, not your connection", hi.Provider, hi.Mbps, lo.Provider, lo.Mbps)}})
		}
	}

	// Bufferbloat.
	type bloat struct {
		dir          string
		inet, router float64
		loss         float64
	}
	var worst *bloat
	for _, dir := range []string{speed.Download, speed.Upload} {
		inet, router, loss, ok := s.WorstLoaded(dir)
		if ok && (worst == nil || inet > worst.inet) {
			worst = &bloat{dir, inet, router, loss}
		}
	}
	if worst != nil && worst.inet >= bloatWarnMs {
		local := worst.router >= 0.5*worst.inet
		ev := []string{
			fmt.Sprintf("Latency rose by %.0f ms while %sing (grade %s; idle it was %.0f ms)", worst.inet, worst.dir, BloatGrade(worst.inet), s.Plan.IdleInternetP50),
			"This is why calls and games lag whenever someone else on the network is downloading or uploading",
		}
		if worst.loss >= 2 {
			ev = append(ev, fmt.Sprintf("%.0f%% of packets were lost under load", worst.loss))
		}
		x := Finding{ID: "bufferbloat", Severity: SevWarn, Impact: 75, Confidence: "high"}
		if local {
			x.Owner = OwnerWiFi
			x.Title = "Latency spikes when the connection is busy (queueing on the local network)"
			x.Evidence = append(ev, fmt.Sprintf("Latency to the router rose by %.0f ms too, so the queue builds on the Wi-Fi or local link", worst.router))
			x.NextSteps = []string{
				"A stronger Wi-Fi connection (or a cable) reduces this; so does a router with airtime fairness or Wi-Fi QoS",
				"Enable Smart Queue Management (SQM) in the router if it has it",
			}
		} else {
			x.Owner = OwnerRouter
			x.Title = "Latency spikes when the connection is busy (bufferbloat)"
			x.Evidence = append(ev, fmt.Sprintf("Latency to the router barely changed (+%.0f ms), so the queue is in the modem or router's internet link", worst.router))
			x.NextSteps = []string{
				"Turn on Smart Queue Management in the router: often called \"Smart Queue\", \"SQM\", \"Adaptive QoS\", \"fq_codel\" or \"cake\"",
				"Set it slightly below your measured speeds so the router, not the modem, manages the queue",
				"If the router has no such setting, a router that supports SQM fixes this for good",
			}
		}
		add(x)
	}
	return out
}

func speedChecks(f facts, findings []Finding) []Check {
	r := f.r
	s := r.Speed
	if s == nil {
		if r.SpeedSkipped != "" {
			return []Check{{Stage: StageSpeed, Name: "Speed", Status: CheckSkip, Detail: "skipped: " + r.SpeedSkipped}}
		}
		return nil
	}
	warned := map[string]bool{}
	for _, x := range findings {
		if x.Severity == SevWarn {
			warned[x.ID] = true
		}
	}
	var cs []Check
	add := func(name string, st CheckStatus, detail string) {
		cs = append(cs, Check{Stage: StageSpeed, Name: name, Status: st, Detail: detail})
	}
	for _, dir := range []string{speed.Download, speed.Upload} {
		name := strings.ToUpper(dir[:1]) + dir[1:]
		best := s.Best(dir)
		if best == nil {
			add(name, CheckFail, "couldn't measure")
			continue
		}
		st := CheckPass
		if warned["slow-"+dir] || warned["slow-"+dir+"-plan"] {
			st = CheckWarn
		}
		add(name, st, providerLine(s, dir))
	}
	var parts []string
	st := CheckPass
	for _, dir := range []string{speed.Download, speed.Upload} {
		if inet, _, _, ok := s.WorstLoaded(dir); ok {
			parts = append(parts, fmt.Sprintf("+%.0f ms %sing (%s)", max(0, inet), dir, BloatGrade(inet)))
		}
	}
	if warned["bufferbloat"] {
		st = CheckWarn
	}
	if len(parts) == 0 {
		add("Latency under load", CheckSkip, "couldn't measure")
	} else {
		add("Latency under load", st, strings.Join(parts, " · "))
	}
	return cs
}

// providerLine: "742 Mbps · Cloudflare 756 · M-Lab NDT7 731".
func providerLine(s *speed.Results, dir string) string {
	best := s.Best(dir)
	var parts []string
	for _, t := range s.Transfers {
		switch {
		case t.Direction != dir:
		case t.OK:
			parts = append(parts, fmt.Sprintf("%s %.0f", t.Provider, t.Mbps))
		case strings.HasPrefix(t.Err, speed.RateLimited):
			parts = append(parts, t.Provider+" rate-limited")
		default:
			parts = append(parts, t.Provider+" failed")
		}
	}
	return fmt.Sprintf("%.0f Mbps · %s", best.Mbps, strings.Join(parts, " · "))
}

func transferErrors(s *speed.Results, dir string) string {
	var parts []string
	for _, t := range s.Transfers {
		if t.Direction == dir && t.Err != "" {
			parts = append(parts, t.Provider+": "+t.Err)
		}
	}
	if len(parts) == 0 {
		return "No provider returned data"
	}
	return strings.Join(parts, "; ")
}

func hasID(fs []Finding, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}
