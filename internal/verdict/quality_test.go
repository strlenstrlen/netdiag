package verdict

import (
	"strings"
	"testing"

	"github.com/strlenstrlen/netdiag/internal/config"
	"github.com/strlenstrlen/netdiag/internal/ladder"
	"github.com/strlenstrlen/netdiag/internal/probe"
	"github.com/strlenstrlen/netdiag/internal/quality"
	"github.com/strlenstrlen/netdiag/internal/snapshot"
)

// series builds a 100-sample latency series at base ms, with spikes and
// losses at the given sequence numbers.
func series(target string, base float64, spikeMs float64, spikes, losses []int) probe.PingResult {
	spike, lost := map[int]bool{}, map[int]bool{}
	for _, s := range spikes {
		spike[s] = true
	}
	for _, s := range losses {
		lost[s] = true
	}
	p := probe.PingResult{Target: target, Method: "icmp"}
	for seq := 1; seq <= 100; seq++ {
		s := probe.Sample{Seq: seq, AtMs: float64(seq-1) * 200}
		switch {
		case lost[seq]:
			s.Lost = true
		case spike[seq]:
			s.RTTMs = spikeMs
		default:
			s.RTTMs = base + float64(seq%3) // a little natural variation
		}
		p.Samples = append(p.Samples, s)
		if !s.Lost {
			p.Received++
			p.RTTsMs = append(p.RTTsMs, s.RTTMs)
		}
	}
	p.Sent = 100
	return p
}

func seqs(from, to, step int) []int {
	var out []int
	for i := from; i <= to; i += step {
		out = append(out, i)
	}
	return out
}

// withQuality attaches a stage-2 result built from the given series.
func withQuality(r *ladder.Results, router probe.PingResult, inet ...probe.PingResult) *quality.Results {
	q := &quality.Results{SeriesSeconds: 20}
	q.Router = &quality.Series{Role: "router", Probe: router, Stats: quality.Summarize(router)}
	for _, p := range inet {
		q.Internet = append(q.Internet, quality.Series{Role: "internet", Probe: p, Stats: quality.Summarize(p)})
	}
	q.Correlation = quality.Correlate(q.Router, q.Internet)
	q.DNS = []quality.DNSTiming{
		{Server: "system", Kind: "system", Queries: 6, Answered: 6, P50Ms: 40},
		{Server: "192.168.1.1", Kind: "configured", Queries: 6, Answered: 6, P50Ms: 40},
		{Server: "1.1.1.1", Kind: "public", Queries: 6, Answered: 6, P50Ms: 30},
		{Server: "8.8.8.8", Kind: "public", Queries: 6, Answered: 6, P50Ms: 35},
	}
	q.HTTP = []quality.HTTPSummary{
		{URL: "https://a.example/", OK: 2, DNSMs: 10, ConnectMs: 15, TLSMs: 30, ServerMs: 40, TotalMs: 100},
		{URL: "https://b.example/", OK: 2, DNSMs: 12, ConnectMs: 18, TLSMs: 35, ServerMs: 60, TotalMs: 130},
	}
	r.Quality = q
	return q
}

func TestQualityScenarios(t *testing.T) {
	healthyRouter := func() probe.PingResult { return series("192.168.1.1", 4, 0, nil, nil) }
	healthyInet := func(ip string) probe.PingResult { return series(ip, 15, 0, nil, nil) }

	tests := []struct {
		name        string
		build       func(r *ladder.Results)
		wantStatus  Status
		wantHead    string // ID of the warning that should become the headline
		wantFinding string
		wantAbsent  string
	}{
		{
			name: "steady network",
			build: func(r *ladder.Results) {
				withQuality(r, healthyRouter(), healthyInet("1.1.1.1"), healthyInet("8.8.8.8"))
			},
			wantStatus: StatusOK,
		},
		{
			name: "Wi-Fi lag: router and internet spike together",
			build: func(r *ladder.Results) {
				sp := seqs(5, 95, 10) // 10 spikes
				withQuality(r, series("192.168.1.1", 4, 150, sp, nil),
					series("1.1.1.1", 15, 160, sp, nil), series("8.8.8.8", 16, 165, sp, nil))
			},
			wantStatus: StatusDegraded, wantHead: "local-lag",
		},
		{
			name: "upstream lag: only internet spikes",
			build: func(r *ladder.Results) {
				sp := seqs(5, 95, 10)
				withQuality(r, healthyRouter(), series("1.1.1.1", 15, 160, sp, nil), series("8.8.8.8", 16, 170, sp, nil))
			},
			wantStatus: StatusDegraded, wantHead: "upstream-lag",
		},
		{
			name: "router answers ping slowly but traffic is fine",
			build: func(r *ladder.Results) {
				withQuality(r, series("192.168.1.1", 4, 150, seqs(5, 95, 10), nil), healthyInet("1.1.1.1"), healthyInet("8.8.8.8"))
			},
			wantStatus: StatusOK, wantFinding: "router-ping-slow", wantAbsent: "local-lag",
		},
		{
			name: "local packet loss",
			build: func(r *ladder.Results) {
				lost := seqs(3, 93, 15) // 7 losses
				withQuality(r, series("192.168.1.1", 4, 0, nil, lost),
					series("1.1.1.1", 15, 0, nil, lost), series("8.8.8.8", 16, 0, nil, lost))
			},
			wantStatus: StatusDegraded, wantHead: "local-loss",
		},
		{
			name: "loss beyond the router",
			build: func(r *ladder.Results) {
				withQuality(r, healthyRouter(),
					series("1.1.1.1", 15, 0, nil, seqs(2, 92, 10)), series("8.8.8.8", 16, 0, nil, seqs(7, 97, 10)))
			},
			wantStatus: StatusDegraded, wantHead: "upstream-loss",
		},
		{
			name: "router drops pings only",
			build: func(r *ladder.Results) {
				withQuality(r, series("192.168.1.1", 4, 0, nil, seqs(3, 93, 15)), healthyInet("1.1.1.1"), healthyInet("8.8.8.8"))
			},
			wantStatus: StatusOK, wantFinding: "router-ping-loss",
		},
		{
			name: "loss outranks lag in the headline",
			build: func(r *ladder.Results) {
				withQuality(r, healthyRouter(),
					series("1.1.1.1", 15, 160, seqs(4, 94, 10), seqs(2, 92, 10)),
					series("8.8.8.8", 16, 170, seqs(4, 94, 10), seqs(7, 97, 10)))
			},
			wantStatus: StatusDegraded, wantHead: "upstream-loss", wantFinding: "upstream-lag",
		},
		{
			name: "satellite-like base latency",
			build: func(r *ladder.Results) {
				withQuality(r, healthyRouter(), series("1.1.1.1", 600, 0, nil, nil), series("8.8.8.8", 620, 0, nil, nil))
			},
			wantStatus: StatusDegraded, wantHead: "high-latency", wantAbsent: "upstream-lag",
		},
		{
			name: "slow router DNS, fast public DNS",
			build: func(r *ladder.Results) {
				q := withQuality(r, healthyRouter(), healthyInet("1.1.1.1"), healthyInet("8.8.8.8"))
				q.DNS[0].P50Ms = 450
			},
			wantStatus: StatusDegraded, wantHead: "dns-slow",
		},
		{
			name: "DNS lookups going unanswered",
			build: func(r *ladder.Results) {
				q := withQuality(r, healthyRouter(), healthyInet("1.1.1.1"), healthyInet("8.8.8.8"))
				q.DNS[0].Answered, q.DNS[0].ErrKinds = 4, []string{"dns-timeout"}
			},
			wantStatus: StatusDegraded, wantHead: "dns-timeouts",
		},
		{
			name: "slow page starts dominated by TLS",
			build: func(r *ladder.Results) {
				q := withQuality(r, healthyRouter(), healthyInet("1.1.1.1"), healthyInet("8.8.8.8"))
				for i := range q.HTTP {
					q.HTTP[i].TLSMs, q.HTTP[i].TotalMs = 1400, 1600
				}
			},
			wantStatus: StatusDegraded, wantHead: "slow-page-start",
		},
		{
			name: "IPv6 much slower than IPv4",
			build: func(r *ladder.Results) {
				q := withQuality(r, healthyRouter(), healthyInet("1.1.1.1"), healthyInet("8.8.8.8"))
				q.Family = &quality.FamilyCompare{V4OK: 10, V6OK: 10, V4P50Ms: 15, V6P50Ms: 140}
			},
			wantStatus: StatusDegraded, wantHead: "ipv6-slow",
		},
		{
			// Seen live: one ~130 ms stall draining over 5 samples on every target.
			name: "single stall is a note, not a lag warning",
			build: func(r *ladder.Results) {
				st := seqs(3, 7, 1)
				withQuality(r, series("192.168.1.1", 4, 130, st, nil),
					series("1.1.1.1", 7, 135, st, nil), series("8.8.8.8", 16, 143, st, nil))
			},
			wantStatus: StatusOK, wantFinding: "brief-stall", wantAbsent: "local-lag",
		},
		{
			name: "stage-1 five-ping estimate yields to the series",
			build: func(r *ladder.Results) {
				r.GatewayPing.RTTsMs = []float64{40, 45, 50, 42, 41} // would trigger gateway-slow alone
				withQuality(r, healthyRouter(), healthyInet("1.1.1.1"), healthyInet("8.8.8.8"))
			},
			wantStatus: StatusOK, wantAbsent: "gateway-slow",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := healthy()
			tc.build(&r)
			v := Evaluate(r)
			if v.Status != tc.wantStatus {
				t.Errorf("status = %s, want %s (headline %q, findings %v)", v.Status, tc.wantStatus, v.Headline, findingIDs(v))
			}
			if tc.wantHead != "" {
				if top := firstWarn(v.Findings); top.ID != tc.wantHead {
					t.Errorf("headline finding = %q, want %q (%q)", top.ID, tc.wantHead, v.Headline)
				}
				if len(v.NextSteps) == 0 && len(v.Evidence) == 0 {
					t.Error("headline finding has no evidence or steps")
				}
			}
			if tc.wantFinding != "" && !hasFinding(v, tc.wantFinding) {
				t.Errorf("missing finding %q; got %v", tc.wantFinding, findingIDs(v))
			}
			if tc.wantAbsent != "" && hasFinding(v, tc.wantAbsent) {
				t.Errorf("unexpected finding %q", tc.wantAbsent)
			}
			resp := 0
			for _, c := range v.Checks {
				if c.Stage == StageResponsiveness {
					resp++
				}
			}
			if resp < 4 {
				t.Errorf("want responsiveness checks, got %d", resp)
			}
		})
	}
}

func TestPeriodicLocalLagOnMacSuggestsAirDrop(t *testing.T) {
	var sp []int
	for seq := 4; seq <= 100; seq += 5 {
		sp = append(sp, seq)
	}
	mk := func(awdl bool, os string) Verdict {
		r := healthy()
		r.Snapshot.OS = os
		r.Snapshot.Interfaces = append(r.Snapshot.Interfaces, snapshot.Interface{Name: "awdl0", Up: awdl, Running: awdl})
		withQuality(&r, series("192.168.1.1", 4, 150, sp, nil), series("1.1.1.1", 15, 160, sp, nil))
		return Evaluate(r)
	}
	v := mk(true, "darwin")
	if firstWarn(v.Findings).ID != "local-lag" {
		t.Fatalf("headline = %q", v.Headline)
	}
	joined := strings.Join(v.Evidence, " ") + strings.Join(v.NextSteps, " ")
	if !strings.Contains(joined, "repeat about every 1.0 seconds") || !strings.Contains(v.NextSteps[0], "AirDrop") {
		t.Errorf("want period evidence and AirDrop as first step; evidence %v steps %v", v.Evidence, v.NextSteps)
	}
	for _, c := range v.Checks {
		if c.Name == "Internet latency" && (c.Status != CheckWarn || !strings.Contains(c.Detail, "local network")) {
			t.Errorf("internet check should point at the local network: %+v", c)
		}
	}
	if strings.Contains(strings.Join(mk(false, "darwin").NextSteps, " "), "AirDrop") {
		t.Error("no AirDrop advice when awdl0 is down")
	}
	if strings.Contains(strings.Join(mk(true, "linux").NextSteps, " "), "AirDrop") {
		t.Error("no AirDrop advice off macOS")
	}
}

func TestShouldRunQuality(t *testing.T) {
	r := healthy()
	if ok, _ := ShouldRunQuality(r); !ok {
		t.Error("healthy network should run stage 2")
	}
	killInternet(&r)
	if ok, why := ShouldRunQuality(r); ok || why == "" {
		t.Error("dead internet should skip stage 2 with a reason")
	}
}

func TestQualityPlanFallsBackToTCP(t *testing.T) {
	r := healthy()
	failPing(&r.GatewayPing)
	failPing(&r.InternetPing[0])         // 1.1.1.1 blocks ping but accepts TCP
	p := r.QualityPlan(config.Default()) // samples 1.1.1.1 and 8.8.8.8
	if p.Router == nil || p.Router.Method != "tcp" || p.Router.Addr != "192.168.1.1:53" {
		t.Errorf("router target = %+v", p.Router)
	}
	if len(p.Internet) != 2 || p.Internet[0].Method != "tcp" || p.Internet[0].Addr != "1.1.1.1:443" || p.Internet[1].Method != "icmp" {
		t.Errorf("internet targets = %+v", p.Internet)
	}
}
