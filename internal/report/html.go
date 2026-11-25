package report

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/strlenstrlen/netdiag/internal/probe"
	"github.com/strlenstrlen/netdiag/internal/quality"
	"github.com/strlenstrlen/netdiag/internal/verdict"
)

//go:embed *.tmpl
var templateFS embed.FS

// dataPlaceholder must not be a comment: html/template strips comments
// inside <script> elements.
const dataPlaceholder = "NETDIAG_DATA_PLACEHOLDER"

var tmpl = template.Must(template.New("netdiag").Funcs(template.FuncMap{
	"mark": func(st verdict.CheckStatus) string {
		switch st {
		case verdict.CheckPass:
			return "✓"
		case verdict.CheckWarn:
			return "!"
		case verdict.CheckFail:
			return "✗"
		}
		return "–"
	},
	"rich": richHTML,
}).ParseFS(templateFS, "*.tmpl"))

// richHTML escapes text and renders `backticked` spans as code. An
// unpaired backtick is kept as plain text.
func richHTML(s string) template.HTML {
	parts := strings.Split(s, "`")
	var b strings.Builder
	for i, p := range parts {
		switch {
		case i%2 == 1 && i < len(parts)-1:
			b.WriteString("<code>" + template.HTMLEscapeString(p) + "</code>")
		case i%2 == 1:
			b.WriteString("`" + template.HTMLEscapeString(p))
		default:
			b.WriteString(template.HTMLEscapeString(p))
		}
	}
	return template.HTML(b.String()) //nolint:gosec // every part is escaped above
}

type htmlView struct {
	Version, Generated, Host, OS, Elapsed, Symptom string
	V                                              verdict.Verdict
	StatusLabel                                    string
	ShowConfidence                                 bool
	Stages                                         []stageView
	Notes                                          []verdict.Finding
	SeriesSeconds                                  int
	Charts                                         []chartView
	CorrelationText                                string
	Speed                                          []speedRow
	IdleLatency, DataMB                            string
	Details                                        []detailTable
	FileHint                                       string
}

type stageView struct {
	Title  string
	Checks []verdict.Check
}

type chartView struct {
	Label, Target, Sub string
	SVG                template.HTML
}

type speedRow struct {
	Direction, Provider, Server string
	OK                          bool
	Mbps                        string
	BarPct                      float64
	Loaded, Data, Err           string
}

type detailTable struct {
	Title string
	Head  []string
	Rows  [][]string
}

// WriteHTML renders a self-contained report: no external resources, with
// the full JSON document embedded so it can be re-read with --from.
// fileHint is the file name shown in the "open it with netdiag" footer.
func WriteHTML(w io.Writer, d Document, fileHint string) error {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "report.html.tmpl", buildView(d, fileHint)); err != nil {
		return err
	}
	// json.Marshal escapes <, > and & as < etc., so the data can't
	// close the <script> element it lives in.
	data, err := json.Marshal(d)
	if err != nil {
		return err
	}
	if bytes.Count(buf.Bytes(), []byte(dataPlaceholder)) != 1 {
		return errors.New("report template lost its data placeholder")
	}
	out := bytes.Replace(buf.Bytes(), []byte(dataPlaceholder), data, 1)
	_, err = w.Write(out)
	return err
}

// ReadDocument loads a report saved as JSON or as HTML with embedded data.
func ReadDocument(path string) (Document, error) {
	var d Document
	b, err := os.ReadFile(path)
	if err != nil {
		return d, err
	}
	if t := bytes.TrimSpace(b); len(t) > 0 && t[0] != '{' {
		const open = `<script type="application/json" id="netdiag-data">`
		i := bytes.Index(b, []byte(open))
		if i < 0 {
			return d, errors.New("no netdiag data found in " + filepath.Base(path))
		}
		b = b[i+len(open):]
		j := bytes.Index(b, []byte("</script>"))
		if j < 0 {
			return d, errors.New("truncated netdiag data in " + filepath.Base(path))
		}
		b = b[:j]
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return d, fmt.Errorf("reading %s: %w", filepath.Base(path), err)
	}
	return d, nil
}

func buildView(d Document, fileHint string) htmlView {
	r, v := d.Results, d.Verdict
	elapsed := r.DurationMs
	if r.Quality != nil {
		elapsed += r.Quality.DurationMs
	}
	if r.Speed != nil {
		elapsed += r.Speed.DurationMs
	}
	view := htmlView{
		Version:        d.Version,
		Generated:      d.GeneratedAt.Format("Jan 2, 2006 at 15:04 MST"),
		Host:           nz(r.Snapshot.Hostname, "unknown host"),
		OS:             osName(r.Snapshot.OS) + " · " + r.Snapshot.Arch,
		Elapsed:        fmt.Sprintf("%.0f s", math.Max(1, elapsed/1000)),
		V:              v,
		ShowConfidence: v.Confidence != "" && v.Status != verdict.StatusOK,
		FileHint:       nz(fileHint, "report.html"),
	}
	if r.Symptom != "" {
		view.Symptom = verdict.SymptomLabel(r.Symptom)
	}
	view.StatusLabel = map[verdict.Status]string{
		verdict.StatusOK: "All clear", verdict.StatusDegraded: "Working, with issues", verdict.StatusFail: "Problem found",
	}[v.Status]

	for _, st := range []struct{ id, title string }{
		{verdict.StageConnectivity, "Connectivity"},
		{verdict.StageResponsiveness, "Responsiveness"},
		{verdict.StageSpeed, "Speed"},
	} {
		var cs []verdict.Check
		for _, c := range v.Checks {
			if c.Stage == st.id {
				cs = append(cs, c)
			}
		}
		if len(cs) > 0 {
			view.Stages = append(view.Stages, stageView{st.title, cs})
		}
	}

	headline := ""
	if v.Status == verdict.StatusDegraded {
		for _, f := range v.Findings {
			if f.Severity == verdict.SevWarn {
				headline = f.ID
				break
			}
		}
	}
	for _, f := range v.Findings {
		if f.ID != headline {
			view.Notes = append(view.Notes, f)
		}
	}

	if q := r.Quality; q != nil {
		view.SeriesSeconds = q.SeriesSeconds
		all := append([]quality.Series{}, q.Internet...)
		if q.Router != nil {
			all = append([]quality.Series{*q.Router}, all...)
		}
		n := 0
		for _, s := range all {
			n = max(n, len(s.Probe.Samples))
		}
		for _, s := range all {
			label := "Internet"
			if s.Role == "router" {
				label = "Router"
			}
			sub := fmt.Sprintf("typical %.0f ms · p95 %.0f ms · %.1f%% lost", s.Stats.P50Ms, s.Stats.P95Ms, s.Stats.LossPct)
			if s.Stats.SpikePeriodMs > 0 {
				sub += fmt.Sprintf(" · spikes every %.1f s", s.Stats.SpikePeriodMs/1000)
			}
			view.Charts = append(view.Charts, chartView{label, quality.HostOnly(s.Probe.Target), sub, seriesSVG(s, n)})
		}
		if c := q.Correlation; c.Computed && c.InternetEvents > 0 {
			view.CorrelationText = fmt.Sprintf("%d of %d moments with internet lag or loss also showed it at the router.",
				c.InternetEventsAtRouter, c.InternetEvents)
		}
	}

	if s := r.Speed; s != nil {
		top := 0.0
		for _, t := range s.Transfers {
			top = math.Max(top, t.Mbps)
		}
		for _, t := range s.Transfers {
			row := speedRow{Direction: titleCase(t.Direction), Provider: t.Provider, Server: t.Server, OK: t.OK, Err: nz(t.Err, "no data")}
			if t.OK {
				row.Mbps = fmt.Sprintf("%.0f", t.Mbps)
				if top > 0 {
					row.BarPct = math.Round(100 * t.Mbps / top)
				}
				row.Loaded = "—"
				if l := t.Loaded; l.Internet != nil && l.Internet.Received > 0 {
					rise := l.Internet.P50Ms - s.Plan.IdleInternetP50
					row.Loaded = fmt.Sprintf("%.0f ms (+%.0f, grade %s)", l.Internet.P50Ms, math.Max(0, rise), verdict.BloatGrade(rise))
				}
				row.Data = fmt.Sprintf("%.0f MB", float64(t.Bytes)/1e6)
			}
			view.Speed = append(view.Speed, row)
		}
		view.IdleLatency = fmt.Sprintf("%.0f ms to the internet and %.0f ms to the router", s.Plan.IdleInternetP50, s.Plan.IdleRouterP50)
		view.DataMB = fmt.Sprintf("%.0f MB", s.DataMB)
		if s.DataMB >= 1000 {
			view.DataMB = fmt.Sprintf("%.1f GB", s.DataMB/1000)
		}
	}

	view.Details = details(d)
	return view
}

// seriesSVG draws one latency series. n is the longest series, so all
// charts share an x axis. The y axis is clipped at 3× the spike threshold
// so one huge stall doesn't flatten everything else. Only numbers go into
// the markup.
func seriesSVG(s quality.Series, n int) template.HTML {
	const w, h, pad = 600.0, 56.0, 4.0
	top := math.Max(s.Stats.SpikeThresholdMs*3, 1)
	x := func(seq int) float64 {
		if n <= 1 {
			return 0
		}
		return float64(seq-1) / float64(n-1) * w
	}
	y := func(v float64) float64 { return h - pad - math.Min(v, top)/top*(h-2*pad) }

	var b strings.Builder
	cls := "l"
	if s.Role != "router" {
		cls = "l inet"
	}
	fmt.Fprintf(&b, `<svg class="spark" viewBox="0 0 %.0f %.0f" preserveAspectRatio="none" role="img" aria-label="latency over time">`, w, h)
	fmt.Fprintf(&b, `<line class="th" x1="0" x2="%.0f" y1="%.1f" y2="%.1f"/>`, w, y(s.Stats.SpikeThresholdMs), y(s.Stats.SpikeThresholdMs))
	var pts []string
	flush := func() {
		if len(pts) > 1 {
			fmt.Fprintf(&b, `<polyline class="%s" points="%s"/>`, cls, strings.Join(pts, " "))
		}
		pts = nil
	}
	for _, smp := range s.Probe.Samples {
		if smp.Lost {
			flush()
			fmt.Fprintf(&b, `<rect class="lost" x="%.1f" y="%.0f" width="3" height="8"/>`, x(smp.Seq)-1.5, h-8)
			continue
		}
		pts = append(pts, fmt.Sprintf("%.1f,%.1f", x(smp.Seq), y(smp.RTTMs)))
	}
	flush()
	b.WriteString(`</svg>`)
	return template.HTML(b.String()) //nolint:gosec // built only from numbers and fixed class names
}

func details(d Document) []detailTable {
	r := d.Results
	sn := r.Snapshot
	var out []detailTable

	cfg := detailTable{Title: "Network configuration", Head: []string{"Item", "Value"}}
	addCfg := func(k, v string) {
		if v != "" {
			cfg.Rows = append(cfg.Rows, []string{k, v})
		}
	}
	for _, it := range sn.Interfaces {
		if it.Usable() {
			addCfg("Interface "+it.Name, fmt.Sprintf("%s · %s · MTU %d", it.Kind, strings.Join(append(append([]string{}, it.IPv4...), it.IPv6...), ", "), it.MTU))
		}
	}
	if sn.DefaultRoute != nil {
		addCfg("Gateway (IPv4)", sn.DefaultRoute.Gateway+" via "+sn.DefaultRoute.Interface)
	}
	if sn.DefaultRoute6 != nil {
		addCfg("Gateway (IPv6)", sn.DefaultRoute6.Gateway+" via "+sn.DefaultRoute6.Interface)
	}
	addCfg("DNS servers", strings.Join(sn.DNSServers, ", "))
	if w := sn.WiFi; w != nil && w.SignalKnown {
		addCfg("Wi-Fi", fmt.Sprintf("%d dBm signal, %d dBm noise · %s ch %d · %d MHz · %s · %.0f Mbps link", w.RSSI, w.Noise, w.Band, w.Channel, w.WidthMHz, w.PHYMode, w.TxRateMbps))
	}
	if sn.VPN.Active {
		addCfg("VPN", strings.Join(sn.VPN.Interfaces, ", ")+map[bool]string{true: " (all traffic)"}[sn.VPN.DefaultRouteViaVPN])
	}
	if sn.Proxy.Any() {
		addCfg("Proxy", fmt.Sprintf("%+v", sn.Proxy))
	}
	if len(sn.Errors) > 0 {
		addCfg("Couldn't collect", strings.Join(sn.Errors, "; "))
	}
	out = append(out, cfg)

	conn := detailTable{Title: "Connectivity probes", Head: []string{"Probe", "Target", "Result"}}
	pings := append([]probe.PingResult{}, r.InternetPing...)
	if r.GatewayTested {
		pings = append([]probe.PingResult{r.GatewayPing}, pings...)
	}
	for _, p := range append(pings, r.InternetPing6...) {
		res := fmt.Sprintf("%d/%d replies", p.Received, p.Sent)
		if p.OK() {
			res += fmt.Sprintf(" · median %.1f ms · max %.1f ms", probe.Median(p.RTTsMs), p.MaxMs())
		} else if p.Err != "" {
			res += " · " + p.Err
		}
		conn.Rows = append(conn.Rows, []string{"Ping", p.Target, res})
	}
	for _, t := range append(append(append([]probe.TCPResult{}, r.GatewayTCP...), r.InternetTCP...), r.InternetTCP6...) {
		res := nz(t.ErrKind, "failed")
		switch {
		case t.Connected:
			res = fmt.Sprintf("connected in %.1f ms", t.RTTMs)
		case t.Refused:
			res = fmt.Sprintf("refused (host alive) in %.1f ms", t.RTTMs)
		}
		conn.Rows = append(conn.Rows, []string{"TCP", t.Target, res})
	}
	for _, c := range r.Captive {
		res := "expected answer"
		switch {
		case !c.Reached:
			res = nz(c.ErrKind, "failed")
		case c.Portal:
			res = fmt.Sprintf("unexpected answer (HTTP %d) %s", c.Status, c.Location)
		}
		conn.Rows = append(conn.Rows, []string{"Sign-in check", c.URL, res})
	}
	for _, h := range r.HTTPS {
		res := fmt.Sprintf("HTTP %d in %.0f ms · %s", h.Status, h.RTTMs, h.Issuer)
		if !h.OK {
			res = nz(h.ErrKind, "failed") + " " + h.Issuer
		}
		conn.Rows = append(conn.Rows, []string{"HTTPS", h.URL, res})
	}
	out = append(out, conn)

	dns := detailTable{Title: "DNS lookups", Head: []string{"Server", "Name", "Time", "Answer"}}
	for _, x := range append(append(append([]probe.DNSResult{}, r.DNSSystem...), r.DNSConfigured...), r.DNSPublic...) {
		ans := nz(x.ErrKind, "failed")
		if x.OK && len(x.Addrs) > 0 {
			ans = x.Addrs[0]
		}
		dns.Rows = append(dns.Rows, []string{x.Server, x.Name, fmt.Sprintf("%.0f ms", x.RTTMs), ans})
	}
	if q := r.Quality; q != nil {
		for _, t := range q.DNS {
			dns.Rows = append(dns.Rows, []string{t.Server + " (" + t.Kind + ")", "new names", fmt.Sprintf("%.0f ms median", t.P50Ms), fmt.Sprintf("%d/%d answered", t.Answered, t.Queries)})
		}
	}
	out = append(out, dns)

	if q := r.Quality; q != nil && len(q.HTTP) > 0 {
		pg := detailTable{Title: "Page start timing", Head: []string{"Site", "Total", "DNS", "Connect", "TLS", "Server"}}
		for _, h := range q.HTTP {
			if h.OK == 0 {
				pg.Rows = append(pg.Rows, []string{h.URL, "failed", "", "", "", ""})
				continue
			}
			ms := func(v float64) string { return fmt.Sprintf("%.0f ms", v) }
			pg.Rows = append(pg.Rows, []string{h.URL, ms(h.TotalMs), ms(h.DNSMs), ms(h.ConnectMs), ms(h.TLSMs), ms(h.ServerMs)})
		}
		out = append(out, pg)
	}
	return out
}

func osName(goos string) string {
	if n, ok := map[string]string{"darwin": "macOS", "linux": "Linux", "windows": "Windows"}[goos]; ok {
		return n
	}
	return goos
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func nz(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// Redact removes identifying details that aren't needed for diagnosis:
// the computer's name and hardware (MAC) addresses.
func Redact(d *Document) {
	d.Results.Snapshot.Hostname = "(redacted)"
	for i := range d.Results.Snapshot.Interfaces {
		d.Results.Snapshot.Interfaces[i].MAC = ""
	}
	d.Redacted = true
}
