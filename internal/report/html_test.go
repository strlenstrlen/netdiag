package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/strlenstrlen/netdiag/internal/ladder"
	"github.com/strlenstrlen/netdiag/internal/probe"
	"github.com/strlenstrlen/netdiag/internal/quality"
	"github.com/strlenstrlen/netdiag/internal/snapshot"
	"github.com/strlenstrlen/netdiag/internal/speed"
	"github.com/strlenstrlen/netdiag/internal/verdict"
)

const evil = `</script><script>alert("x")</script><img src=x onerror=alert(1)>`

func sampleDoc() Document {
	series := func(target string, base float64, spikeEvery int) probe.PingResult {
		var p probe.PingResult
		p.Target, p.Method = target, "icmp"
		for seq := 1; seq <= 100; seq++ {
			s := probe.Sample{Seq: seq, AtMs: float64(seq-1) * 200, RTTMs: base}
			if seq%spikeEvery == 0 {
				s.RTTMs = 150
			}
			if seq == 50 {
				s = probe.Sample{Seq: seq, AtMs: s.AtMs, Lost: true}
			}
			p.Samples = append(p.Samples, s)
		}
		b, _ := p.MarshalJSON() // round-trip to derive counts and RTTs
		_ = p.UnmarshalJSON(b)
		return p
	}
	router, inet := series("192.168.1.1", 4, 5), series("1.1.1.1", 12, 5)
	q := &quality.Results{SeriesSeconds: 20,
		Router:   &quality.Series{Role: "router", Probe: router, Stats: quality.Summarize(router)},
		Internet: []quality.Series{{Role: "internet", Probe: inet, Stats: quality.Summarize(inet)}},
	}
	q.Correlation = quality.Correlate(q.Router, q.Internet)
	r := ladder.Results{
		Symptom: "slow",
		Snapshot: snapshot.Snapshot{
			OS: "darwin", Arch: "arm64", Hostname: evil,
			Interfaces:       []snapshot.Interface{{Name: "en0", Kind: snapshot.KindWiFi, Up: true, MAC: "02:00:00:00:00:02", IPv4: []string{"192.168.1.20"}}},
			PrimaryInterface: "en0",
			DefaultRoute:     &snapshot.Route{Gateway: "192.168.1.1", Interface: "en0"},
			DNSServers:       []string{"192.168.1.1"},
		},
		GatewayTested: true,
		GatewayPing:   router,
		InternetTCP:   []probe.TCPResult{{Target: "1.1.1.1:443", Connected: true, RTTMs: 12}},
		HTTPS:         []probe.HTTPSResult{{URL: "https://example.com/" + evil, OK: true, Status: 200}},
		Quality:       q,
		Speed: &speed.Results{
			Plan: speed.Plan{IdleInternetP50: 12, IdleRouterP50: 4},
			Transfers: []speed.Transfer{
				{Provider: speed.ProviderCloudflare, Direction: speed.Download, OK: true, Mbps: 500, Bytes: 250e6,
					Loaded: speed.Loaded{Internet: &quality.Stats{Received: 20, P50Ms: 40}}},
				{Provider: speed.ProviderMLab, Direction: speed.Upload, Err: speed.RateLimited + " (try later)"},
			},
			DataMB: 250,
		},
	}
	return NewDocument(r, verdict.Evaluate(r))
}

func render(t *testing.T, d Document) string {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteHTML(&buf, d, "report.html"); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestHTMLEscapesEverything(t *testing.T) {
	out := render(t, sampleDoc())
	if n := strings.Count(out, "<script"); n != 1 {
		t.Errorf("found %d <script tags; only the data block should exist", n)
	}
	if strings.Contains(out, "<img") || strings.Contains(out, `alert("x")</script>`) {
		t.Error("untrusted text reached the page unescaped")
	}
	for _, want := range []string{"<svg class=\"spark\"", "Network report", "Working, with issues", "rate-limited", "</html>"} {
		if !strings.Contains(out, want) {
			t.Errorf("report is missing %q", want)
		}
	}
	if strings.Contains(out, "http://") && strings.Contains(out, "src=\"http") {
		t.Error("report must not load external resources")
	}
}

func TestEmbeddedDataRoundTrip(t *testing.T) {
	d := sampleDoc()
	dir := t.TempDir()
	html := filepath.Join(dir, "r.html")
	if err := os.WriteFile(html, []byte(render(t, d)), 0o600); err != nil {
		t.Fatal(err)
	}
	back, err := ReadDocument(html)
	if err != nil {
		t.Fatal(err)
	}
	if back.Results.Snapshot.Hostname != evil || back.Verdict.Headline != d.Verdict.Headline {
		t.Errorf("round trip changed data: host %q headline %q", back.Results.Snapshot.Hostname, back.Verdict.Headline)
	}
	if q := back.Results.Quality; q == nil || q.Router == nil || len(q.Router.Probe.RTTsMs) != 99 {
		t.Error("latency samples didn't survive the round trip")
	}

	js := filepath.Join(dir, "r.json")
	f, _ := os.Create(js)
	_ = WriteJSON(f, d)
	f.Close()
	if back, err := ReadDocument(js); err != nil || back.Verdict.Status != d.Verdict.Status {
		t.Errorf("reading JSON: %v", err)
	}
	if _, err := ReadDocument(filepath.Join(dir, "missing.html")); err == nil {
		t.Error("missing file should error")
	}
}

func TestRichRendersCodeAndEscapes(t *testing.T) {
	got := string(richHTML("run `sudo ifconfig awdl0 down` then <b>`x`"))
	want := "run <code>sudo ifconfig awdl0 down</code> then &lt;b&gt;<code>x</code>"
	if got != want {
		t.Errorf("rich = %q", got)
	}
	if got := string(richHTML("odd ` backtick <i>")); got != "odd ` backtick &lt;i&gt;" {
		t.Errorf("unpaired backtick: %q", got)
	}
}

func TestRedact(t *testing.T) {
	d := sampleDoc()
	Redact(&d)
	out := render(t, d)
	if strings.Contains(out, "02:00:00:00:00:02") {
		t.Error("redacted report still contains the MAC address")
	}
	meta := out[strings.Index(out, `<div class="meta">`):strings.Index(out, `<section class="card verdict`)]
	if strings.Contains(meta, "onerror") || !strings.Contains(meta, "(redacted)") || !d.Redacted {
		t.Error("redaction should be visible")
	}
}
