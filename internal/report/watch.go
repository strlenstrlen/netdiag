package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/strlenstrlen/netdiag/internal/probe"
	"github.com/strlenstrlen/netdiag/internal/watch"
)

const (
	ToolTriage = "netdiag"
	ToolWatch  = "netdiag-watch"
)

// WatchDocument is a saved watch run.
type WatchDocument struct {
	Tool        string        `json:"tool"`
	Version     string        `json:"version"`
	GeneratedAt time.Time     `json:"generated_at"`
	Redacted    bool          `json:"redacted,omitempty"`
	Results     watch.Results `json:"results"`
}

func NewWatchDocument(r watch.Results) WatchDocument {
	return WatchDocument{Tool: ToolWatch, Version: Version, GeneratedAt: time.Now(), Results: r}
}

func RedactWatch(d *WatchDocument) {
	d.Results.Snapshot.Hostname = "(redacted)"
	for i := range d.Results.Snapshot.Interfaces {
		d.Results.Snapshot.Interfaces[i].MAC = ""
	}
	d.Redacted = true
}

// ReadAny loads a saved triage or watch report (JSON or HTML) and returns
// a Document or a WatchDocument.
func ReadAny(path string) (any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if t := bytes.TrimSpace(b); len(t) > 0 && t[0] != '{' {
		const open = `<script type="application/json" id="netdiag-data">`
		i := bytes.Index(b, []byte(open))
		if i < 0 {
			return nil, errors.New("no netdiag data found in " + filepath.Base(path))
		}
		b = b[i+len(open):]
		j := bytes.Index(b, []byte("</script>"))
		if j < 0 {
			return nil, errors.New("truncated netdiag data in " + filepath.Base(path))
		}
		b = b[:j]
	}
	var head struct {
		Tool string `json:"tool"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return nil, fmt.Errorf("reading %s: %w", filepath.Base(path), err)
	}
	if head.Tool == ToolWatch {
		var d WatchDocument
		err := json.Unmarshal(b, &d)
		return d, err
	}
	var d Document
	err = json.Unmarshal(b, &d)
	return d, err
}

type watchView struct {
	Version, Started, Duration, Host, OS string
	C                                    watchConclusion
	StatusClass, StatusLabel             string
	Stats                                []kv
	Timeline                             template.HTML
	Axis                                 []string
	ClipMs                               int
	Events                               []eventRow
	Targets, Interval, FileHint          string
}

type watchConclusion struct {
	Headline, Owner     string
	Evidence, NextSteps []string
}

type kv struct{ K, V string }

type eventRow struct {
	Time, Dur, Title, Detail, Cause, CauseLabel string
}

var causeLabels = map[string]string{
	watch.CauseLocal: "local network", watch.CauseWiFi: "Wi-Fi", watch.CauseUpstream: "beyond the router",
	watch.CauseDNS: "DNS", watch.CauseConfig: "settings change",
}

func WriteWatchHTML(w io.Writer, d WatchDocument, fileHint string) error {
	r := d.Results
	s := r.Summary
	c := s.Conclusion
	v := watchView{
		Version:     d.Version,
		Started:     r.Started.Format("Jan 2, 2006 at 15:04 MST"),
		Duration:    humanDur(time.Duration(s.DurationSec * float64(time.Second))),
		Host:        nz(r.Snapshot.Hostname, "unknown host"),
		OS:          osName(r.Snapshot.OS),
		C:           watchConclusion{c.Headline, c.Owner, c.Evidence, c.NextSteps},
		StatusClass: map[string]string{"ok": "ok", "warn": "degraded", "fail": "fail"}[c.Status],
		StatusLabel: map[string]string{"ok": "No drops", "warn": "Some trouble", "fail": "Drops found"}[c.Status],
		Targets:     strings.Join(r.Internet, " and "),
		Interval:    humanDur(time.Duration(r.IntervalMs) * time.Millisecond),
		FileHint:    nz(fileHint, "watch.html"),
	}
	v.Stats = []kv{
		{"uptime", fmt.Sprintf("%.1f%%", s.UptimePct)},
		{"outages", fmt.Sprint(s.Outages)},
		{"longest outage", humanDur(time.Duration(s.LongestOutageSec) * time.Second)},
		{"high-latency episodes", fmt.Sprint(s.LagEpisodes)},
		{"Wi-Fi events", fmt.Sprint(s.WiFiEvents)},
		{"typical internet latency", fmt.Sprintf("%.0f ms", s.InetP50Ms)},
		{"internet probes lost", fmt.Sprintf("%.1f%%", s.InetLossPct)},
	}
	if s.Outages == 0 {
		v.Stats[2].V = "—"
	}
	v.Timeline, v.ClipMs = timelineSVG(r)
	if len(r.Ticks) > 1 {
		a, b := r.Ticks[0].At, r.Ticks[len(r.Ticks)-1].At
		v.Axis = []string{a.Format("15:04:05"), a.Add(b.Sub(a) / 2).Format("15:04:05"), b.Format("15:04:05")}
	}
	for _, e := range r.Events {
		row := eventRow{Time: e.Start.Format("15:04:05"), Title: e.Title, Detail: e.Detail, Cause: e.Cause, CauseLabel: causeLabels[e.Cause]}
		if dd := e.Duration(); dd > 0 {
			row.Dur = "until " + e.End.Format("15:04:05")
		}
		v.Events = append(v.Events, row)
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "watch.html.tmpl", v); err != nil {
		return err
	}
	data, err := json.Marshal(d)
	if err != nil {
		return err
	}
	if bytes.Count(buf.Bytes(), []byte(dataPlaceholder)) != 1 {
		return errors.New("watch template lost its data placeholder")
	}
	_, err = w.Write(bytes.Replace(buf.Bytes(), []byte(dataPlaceholder), data, 1))
	return err
}

// timelineSVG draws internet and router latency over the whole run with
// outages and lag shaded. Long runs are bucketed to at most 800 columns,
// keeping each bucket's worst value so spikes stay visible.
func timelineSVG(r watch.Results) (template.HTML, int) {
	const w, h, pad = 800.0, 170.0, 6.0
	n := len(r.Ticks)
	if n < 2 {
		return template.HTML(`<svg class="timeline" viewBox="0 0 800 170"></svg>`), 0
	}
	start, end := r.Ticks[0].At, r.Ticks[n-1].At
	span := end.Sub(start).Seconds()
	xOf := func(t time.Time) float64 { return math.Max(0, math.Min(w, t.Sub(start).Seconds()/span*w)) }

	var inet []float64
	for _, t := range r.Ticks {
		if t.Inet != nil {
			inet = append(inet, *t.Inet)
		}
	}
	clip := math.Min(1000, math.Max(100, probe.Percentile(inet, 99)*1.3))
	clip = math.Ceil(clip/50) * 50
	yOf := func(v float64) float64 { return h - pad - math.Min(v, clip)/clip*(h-2*pad) }

	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="timeline" viewBox="0 0 %.0f %.0f" preserveAspectRatio="none" role="img" aria-label="latency timeline">`, w, h)
	for _, e := range r.Events {
		switch e.Kind {
		case "outage", "lag":
			x1, x2 := xOf(e.Start), xOf(e.End)
			cls := "out"
			if e.Kind == "lag" {
				cls = "lag"
			}
			fmt.Fprintf(&b, `<rect class="%s" x="%.1f" y="0" width="%.1f" height="%.0f"/>`, cls, x1, math.Max(2, x2-x1), h)
		case "wifi", "signal", "ip", "gateway", "vpn":
			x := xOf(e.Start)
			fmt.Fprintf(&b, `<line class="ev" x1="%.1f" x2="%.1f" y1="0" y2="%.0f"/>`, x, x, h)
		}
	}
	buckets := min(n, 800)
	line := func(cls string, get func(watch.Tick) *float64) {
		var pts []string
		flush := func() {
			if len(pts) > 1 {
				fmt.Fprintf(&b, `<polyline class="%s" points="%s"/>`, cls, strings.Join(pts, " "))
			}
			pts = nil
		}
		for k := 0; k < buckets; k++ {
			lo, hi := k*n/buckets, (k+1)*n/buckets
			worst, lost := -1.0, false
			for _, t := range r.Ticks[lo:hi] {
				if v := get(t); v != nil {
					worst = math.Max(worst, *v)
				} else {
					lost = true
				}
			}
			if worst < 0 || (lost && hi-lo == 1) {
				flush()
				continue
			}
			pts = append(pts, fmt.Sprintf("%.1f,%.1f", xOf(r.Ticks[lo].At), yOf(worst)))
		}
		flush()
	}
	if r.Router != "" {
		line("l router", func(t watch.Tick) *float64 { return t.Router })
	}
	line("l", func(t watch.Tick) *float64 { return t.Inet })
	b.WriteString(`</svg>`)
	return template.HTML(b.String()), int(clip) //nolint:gosec // numbers and fixed class names only
}

// WriteWatchConsole prints a watch run's summary and events.
func WriteWatchConsole(w io.Writer, d WatchDocument, color bool) {
	s := style{on: color}
	r := d.Results
	c := r.Summary.Conclusion
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }
	p("")
	p("%s  %s", s.bold("netdiag watch "+d.Version), s.dim(fmt.Sprintf("%s · %s", r.Started.Format("2006-01-02 15:04"), humanDur(time.Duration(r.Summary.DurationSec*float64(time.Second))))))
	p("")
	badge := map[string]string{"ok": s.green(s.bold("✓ NO DROPS")), "warn": s.yellow(s.bold("! SOME TROUBLE")), "fail": s.red(s.bold("✗ DROPS FOUND"))}[c.Status]
	p("%s", badge)
	p("%s", s.bold(c.Headline))
	if c.Owner != "" {
		p("%s", s.dim("Who can fix it: "+c.Owner))
	}
	if len(c.Evidence) > 0 {
		p("")
		p("%s", s.bold("What happened:"))
		for _, e := range c.Evidence {
			p("  • %s", e)
		}
	}
	if len(c.NextSteps) > 0 {
		p("")
		p("%s", s.bold("What to do:"))
		for i, n := range c.NextSteps {
			p("  %d. %s", i+1, n)
		}
	}
	if len(r.Events) > 0 {
		p("")
		p("%s", s.bold("Events"))
		for _, e := range r.Events {
			where := ""
			if l := causeLabels[e.Cause]; l != "" {
				where = s.dim(" · " + l)
			}
			p("  %s  %s%s", e.Start.Format("15:04:05"), e.Title, where)
		}
	}
	sm := r.Summary
	p("")
	p("%s", s.dim(fmt.Sprintf("Uptime %.1f%% · internet %.0f ms typical, %.0f ms p95 · %.1f%% of probes lost · router %.0f ms, %.1f%% lost",
		sm.UptimePct, sm.InetP50Ms, sm.InetP95Ms, sm.InetLossPct, sm.RouterP50Ms, sm.RouterLossPct)))
	p("")
}

func humanDur(d time.Duration) string {
	switch {
	case d <= 0:
		return "0 s"
	case d < time.Minute:
		return fmt.Sprintf("%.0f s", d.Seconds())
	case d < time.Hour:
		return fmt.Sprintf("%d min %d s", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%d h %d min", int(d.Hours()), int(d.Minutes())%60)
}
