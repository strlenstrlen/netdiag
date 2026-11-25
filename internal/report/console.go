// Package report renders results for people (console) and machines (JSON).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/strlenstrlen/netdiag/internal/ladder"
	"github.com/strlenstrlen/netdiag/internal/probe"
	"github.com/strlenstrlen/netdiag/internal/quality"
	"github.com/strlenstrlen/netdiag/internal/verdict"
)

const Version = "0.1.0"

// Document is the JSON report: everything needed to re-render or analyze a
// run on another machine.
type Document struct {
	Tool        string          `json:"tool"`
	Version     string          `json:"version"`
	GeneratedAt time.Time       `json:"generated_at"`
	Redacted    bool            `json:"redacted,omitempty"`
	Verdict     verdict.Verdict `json:"verdict"`
	Results     ladder.Results  `json:"results"`
}

func NewDocument(r ladder.Results, v verdict.Verdict) Document {
	return Document{Tool: "netdiag", Version: Version, GeneratedAt: time.Now(), Verdict: v, Results: r}
}

func WriteJSON(w io.Writer, d Document) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(d)
}

type style struct{ on bool }

func (s style) c(code, txt string) string {
	if !s.on {
		return txt
	}
	return "\x1b[" + code + "m" + txt + "\x1b[0m"
}
func (s style) bold(t string) string   { return s.c("1", t) }
func (s style) dim(t string) string    { return s.c("2", t) }
func (s style) red(t string) string    { return s.c("31", t) }
func (s style) green(t string) string  { return s.c("32", t) }
func (s style) yellow(t string) string { return s.c("33", t) }
func (s style) cyan(t string) string   { return s.c("36", t) }

func (s style) mark(st verdict.CheckStatus) string {
	switch st {
	case verdict.CheckPass:
		return s.green("✓")
	case verdict.CheckWarn:
		return s.yellow("!")
	case verdict.CheckFail:
		return s.red("✗")
	}
	return s.dim("–")
}

// WriteConsole prints the human-readable report.
func WriteConsole(w io.Writer, d Document, color, verbose bool) {
	s := style{on: color}
	v, r := d.Verdict, d.Results
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }

	p("")
	elapsed := r.DurationMs
	if r.Quality != nil {
		elapsed += r.Quality.DurationMs
	}
	if r.Speed != nil {
		elapsed += r.Speed.DurationMs
	}
	p("%s  %s", s.bold("netdiag "+d.Version), s.dim(fmt.Sprintf("%s · %s/%s · %.1fs", d.GeneratedAt.Format("2006-01-02 15:04"), r.Snapshot.OS, r.Snapshot.Arch, elapsed/1000)))
	if r.Symptom != "" {
		p("%s %s", s.dim("Reported problem:"), verdict.SymptomLabel(r.Symptom))
	}
	p("")

	var badge string
	switch v.Status {
	case verdict.StatusFail:
		badge = s.red(s.bold("✗ PROBLEM FOUND"))
	case verdict.StatusDegraded:
		badge = s.yellow(s.bold("! WORKING, WITH ISSUES"))
	default:
		badge = s.green(s.bold("✓ ALL CLEAR"))
	}
	p("%s", badge)
	p("%s", s.bold(v.Headline))
	var meta []string
	if v.Owner != "" {
		meta = append(meta, "Who can fix it: "+v.Owner)
	}
	if v.Confidence != "" && v.Status != verdict.StatusOK {
		meta = append(meta, "Confidence: "+v.Confidence)
	}
	if len(meta) > 0 {
		p("%s", s.dim(strings.Join(meta, "   ")))
	}

	if len(v.Evidence) > 0 {
		p("")
		p("%s", s.bold("Why:"))
		for _, e := range v.Evidence {
			p("  • %s", e)
		}
	}
	if len(v.NextSteps) > 0 {
		p("")
		p("%s", s.bold("What to do:"))
		for i, n := range v.NextSteps {
			p("  %d. %s", i+1, n)
		}
	}

	width := 0
	for _, c := range v.Checks {
		width = max(width, len(c.Name))
	}
	for _, stage := range []struct{ id, title string }{
		{verdict.StageConnectivity, "Connectivity"},
		{verdict.StageResponsiveness, "Responsiveness"},
		{verdict.StageSpeed, "Speed"},
	} {
		header := false
		for _, c := range v.Checks {
			if c.Stage != stage.id {
				continue
			}
			if !header {
				p("")
				p("%s", s.bold(stage.title))
				header = true
			}
			p("  %s %-*s  %s", s.mark(c.Status), width, c.Name, s.dim(c.Detail))
		}
	}

	// Secondary findings, skipping the one already shown as the headline.
	var notes []verdict.Finding
	for _, f := range v.Findings {
		if v.Status == verdict.StatusDegraded && f.Title == firstWarnTitle(v.Findings) {
			continue
		}
		notes = append(notes, f)
	}
	if len(notes) > 0 {
		p("")
		p("%s", s.bold("Also noticed"))
		for _, f := range notes {
			m := s.cyan("i")
			if f.Severity == verdict.SevWarn {
				m = s.yellow("!")
			}
			p("  %s %s", m, f.Title)
			for _, e := range f.Evidence {
				if e != "" {
					p("    %s", s.dim(e))
				}
			}
			if verbose {
				for _, n := range f.NextSteps {
					p("    → %s", n)
				}
			}
		}
	}

	if verbose {
		writeDetails(w, s, r)
	}
	if r.Speed != nil {
		p("")
		p("%s", s.dim(fmt.Sprintf("Speed test used %.0f MB of data", r.Speed.DataMB)))
	}
	if len(r.Snapshot.Errors) > 0 {
		p("")
		p("%s", s.dim("Couldn't collect: "+strings.Join(r.Snapshot.Errors, "; ")))
	}
	p("")
}

func firstWarnTitle(fs []verdict.Finding) string {
	for _, f := range fs {
		if f.Severity == verdict.SevWarn {
			return f.Title
		}
	}
	return ""
}

func writeDetails(w io.Writer, s style, r ladder.Results) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }
	sec := func(t string) { p(""); p("%s", s.bold(t)) }

	sec("Configuration")
	sn := r.Snapshot
	if sn.DefaultRoute != nil {
		p("  IPv4 gateway   %s via %s", sn.DefaultRoute.Gateway, sn.DefaultRoute.Interface)
	}
	if sn.DefaultRoute6 != nil {
		p("  IPv6 gateway   %s via %s", sn.DefaultRoute6.Gateway, sn.DefaultRoute6.Interface)
	}
	p("  DNS servers    %s %s", strings.Join(sn.DNSServers, ", "), s.dim("("+sn.DNSSource+")"))
	for _, it := range sn.Interfaces {
		if it.Usable() {
			p("  %-14s %s %s %s", it.Name, it.Kind, strings.Join(append(it.IPv4, it.IPv6...), " "), s.dim(fmt.Sprintf("mtu %d", it.MTU)))
		}
	}

	sec("Ping")
	pings := append([]probe.PingResult{}, r.InternetPing...)
	if r.GatewayTested {
		pings = append([]probe.PingResult{r.GatewayPing}, pings...)
	}
	pings = append(pings, r.InternetPing6...)
	for _, pr := range pings {
		if pr.OK() {
			p("  %-24s %d/%d  avg %.1f  min %.1f  max %.1f  jitter %.1f ms", pr.Target, pr.Received, pr.Sent, pr.AvgMs(), pr.MinMs(), pr.MaxMs(), pr.JitterMs())
		} else {
			p("  %-24s %d/%d  %s", pr.Target, pr.Received, pr.Sent, s.dim(pr.Err))
		}
	}

	sec("TCP connect")
	tcps := append(append(append([]probe.TCPResult{}, r.GatewayTCP...), r.InternetTCP...), r.InternetTCP6...)
	for _, t := range tcps {
		switch {
		case t.Connected:
			p("  %-32s connected %.1f ms", t.Target, t.RTTMs)
		case t.Refused:
			p("  %-32s refused (host alive) %.1f ms", t.Target, t.RTTMs)
		default:
			p("  %-32s %s", t.Target, s.dim(t.ErrKind))
		}
	}

	sec("DNS")
	all := append(append(append([]probe.DNSResult{}, r.DNSSystem...), r.DNSConfigured...), r.DNSPublic...)
	for _, d := range all {
		if d.OK {
			first := d.Addrs[0]
			p("  %-14s %-20s %6.1f ms  %s", d.Server, d.Name, d.RTTMs, s.dim(first))
		} else {
			p("  %-14s %-20s %6.1f ms  %s", d.Server, d.Name, d.RTTMs, s.dim(d.ErrKind))
		}
	}

	sec("HTTP")
	for _, c := range r.Captive {
		state := "expected answer"
		if !c.Reached {
			state = c.ErrKind
		} else if c.Portal {
			state = fmt.Sprintf("UNEXPECTED (HTTP %d %s)", c.Status, c.Location)
		}
		p("  %-50s %6.1f ms  %s", c.URL, c.RTTMs, state)
	}
	for _, h := range r.HTTPS {
		state := fmt.Sprintf("HTTP %d", h.Status)
		if !h.OK {
			state = h.ErrKind
		}
		p("  %-50s %6.1f ms  %s %s", h.URL, h.RTTMs, state, s.dim(h.Issuer))
	}
	if r.ClockSkewKnown {
		p("  clock skew vs servers: %.0f s", r.ClockSkewSec)
	}

	q := r.Quality
	if q == nil {
		return
	}
	sec(fmt.Sprintf("Latency series (%d s, sampled together)", q.SeriesSeconds))
	seriesList := q.Internet
	if q.Router != nil {
		seriesList = append([]quality.Series{*q.Router}, seriesList...)
	}
	for _, x := range seriesList {
		st := x.Stats
		p("  %-8s %-18s %-4s p50 %5.1f  p95 %5.1f  max %6.1f  jitter %5.1f ms  loss %4.1f%%  spikes %d (>%.0f ms)",
			x.Role, quality.HostOnly(x.Probe.Target), x.Probe.Method, st.P50Ms, st.P95Ms, st.MaxMs, st.JitterMs, st.LossPct, st.Spikes, st.SpikeThresholdMs)
		p("           %s", s.dim(sparkline(x)))
	}
	if c := q.Correlation; c.Computed {
		p("  %s", s.dim(fmt.Sprintf("internet trouble moments: %d, at the same time as router trouble: %d · router-only trouble moments: %d",
			c.InternetEvents, c.InternetEventsAtRouter, c.RouterOnlyEvents)))
	}

	sec("DNS first-lookup timing (uncached names)")
	for _, d := range q.DNS {
		extra := ""
		if len(d.ErrKinds) > 0 {
			extra = s.dim(" " + strings.Join(d.ErrKinds, ", "))
		}
		p("  %-10s %-14s %d/%d answered  p50 %6.1f  max %6.1f ms%s", d.Kind, d.Server, d.Answered, d.Queries, d.P50Ms, d.MaxMs, extra)
	}

	sec("Page start timing (median per site)")
	for _, h := range q.HTTP {
		if h.OK == 0 {
			p("  %-50s %s", h.URL, s.dim("failed"))
			continue
		}
		p("  %-50s total %6.1f  DNS %5.1f  connect %5.1f  TLS %6.1f  server %6.1f ms", h.URL, h.TotalMs, h.DNSMs, h.ConnectMs, h.TLSMs, h.ServerMs)
	}

	if f := q.Family; f != nil {
		sec("IPv4 vs IPv6 (TCP connect)")
		p("  IPv4 p50 %.1f ms (%d ok) · IPv6 p50 %.1f ms (%d ok)", f.V4P50Ms, f.V4OK, f.V6P50Ms, f.V6OK)
	}

	sp := r.Speed
	if sp == nil {
		return
	}
	sec(fmt.Sprintf("Speed (idle latency: router %.0f ms, internet %.0f ms)", sp.Plan.IdleRouterP50, sp.Plan.IdleInternetP50))
	for _, t := range sp.Transfers {
		if !t.OK {
			p("  %-8s %-11s %s", t.Direction, t.Provider, s.dim("failed: "+t.Err))
			continue
		}
		extra := ""
		if t.Capped {
			extra = " · hit data cap"
		}
		if t.ClientMbps > 0 {
			extra += fmt.Sprintf(" · client-side %.0f Mbps", t.ClientMbps)
		}
		p("  %-8s %-11s %7.1f Mbps  %5.0f MB in %4.1fs · %d %s · %s%s", t.Direction, t.Provider, t.Mbps,
			float64(t.Bytes)/1e6, t.DurationMs/1000, t.Streams, plural(t.Streams, "stream", "streams"), t.Server, s.dim(extra))
		if l := t.Loaded; l.Internet != nil {
			line := fmt.Sprintf("under load: internet p50 %.0f ms p95 %.0f ms loss %.0f%%", l.Internet.P50Ms, l.Internet.P95Ms, l.Internet.LossPct)
			if l.Router != nil {
				line += fmt.Sprintf(" · router p50 %.0f ms", l.Router.P50Ms)
			}
			p("           %s", s.dim(line))
		}
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// sparkline draws a series as one character per sample so spikes and
// losses can be lined up across series by eye. "×" marks a lost packet.
func sparkline(x quality.Series) string {
	const bars = "▁▂▃▄▅▆▇█"
	levels := []rune(bars)
	// Fixed scale per series: full height at 3× the spike threshold, so one
	// huge stall doesn't flatten every ordinary spike into the baseline.
	top := x.Stats.SpikeThresholdMs * 3
	var b strings.Builder
	for _, sm := range x.Probe.Samples {
		if sm.Lost {
			b.WriteRune('×')
			continue
		}
		i := int(sm.RTTMs / top * float64(len(levels)-1))
		b.WriteRune(levels[min(max(i, 0), len(levels)-1)])
	}
	return b.String()
}
