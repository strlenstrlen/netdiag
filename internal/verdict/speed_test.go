package verdict

import (
	"strings"
	"testing"

	"github.com/strlenstrlen/netdiag/internal/ladder"
	"github.com/strlenstrlen/netdiag/internal/quality"
	"github.com/strlenstrlen/netdiag/internal/speed"
)

// xfer builds a successful transfer with latency measured under load.
func xfer(provider, dir string, mbps, routerLoaded, inetLoaded float64) speed.Transfer {
	stats := func(p50 float64) *quality.Stats {
		return &quality.Stats{Sent: 30, Received: 30, P50Ms: p50, P95Ms: p50 * 1.5}
	}
	return speed.Transfer{Provider: provider, Direction: dir, OK: true, Mbps: mbps, Bytes: 100e6, DurationMs: 8000,
		Loaded: speed.Loaded{Router: stats(routerLoaded), Internet: stats(inetLoaded)}}
}

// withSpeed adds healthy stage-2 results and the given stage-3 transfers
// (idle latency: router 4 ms, internet 15 ms).
func withSpeed(r *ladder.Results, plan speed.Plan, ts ...speed.Transfer) *speed.Results {
	withQuality(r, series("192.168.1.1", 4, 0, nil, nil), series("1.1.1.1", 15, 0, nil, nil), series("8.8.8.8", 16, 0, nil, nil))
	plan.IdleRouterP50, plan.IdleInternetP50 = 4, 15
	s := &speed.Results{Plan: plan, Transfers: ts, DataMB: 400}
	r.Speed = s
	return s
}

func TestSpeedScenarios(t *testing.T) {
	cf, ml := speed.ProviderCloudflare, speed.ProviderMLab
	dn, up := speed.Download, speed.Upload
	tests := []struct {
		name        string
		build       func(r *ladder.Results)
		wantStatus  Status
		wantHead    string
		wantOwner   string
		wantFinding string
		wantAbsent  string
	}{
		{
			name: "healthy line",
			build: func(r *ladder.Results) {
				withSpeed(r, speed.Plan{}, xfer(cf, dn, 300, 6, 20), xfer(ml, dn, 290, 6, 22), xfer(cf, up, 40, 5, 25), xfer(ml, up, 42, 5, 24))
			},
			wantStatus: StatusOK,
		},
		{
			name: "slow download",
			build: func(r *ladder.Results) {
				withSpeed(r, speed.Plan{}, xfer(cf, dn, 6, 5, 20), xfer(ml, dn, 5.5, 5, 20), xfer(cf, up, 5, 5, 20))
			},
			wantStatus: StatusDegraded, wantHead: "slow-download", wantOwner: OwnerISP,
		},
		{
			name: "slow upload hurts calls",
			build: func(r *ladder.Results) {
				withSpeed(r, speed.Plan{}, xfer(cf, dn, 100, 5, 20), xfer(cf, up, 1.2, 5, 20))
			},
			wantStatus: StatusDegraded, wantHead: "slow-upload",
		},
		{
			name: "well under the plan",
			build: func(r *ladder.Results) {
				withSpeed(r, speed.Plan{PlanDownMbps: 1000}, xfer(cf, dn, 200, 5, 20), xfer(cf, up, 40, 5, 20))
			},
			wantStatus: StatusDegraded, wantHead: "slow-download-plan", wantOwner: OwnerISP,
		},
		{
			name: "under plan because Wi-Fi is the limit",
			build: func(r *ladder.Results) {
				r.Snapshot.WiFi.TxRateMbps = 400
				withSpeed(r, speed.Plan{PlanDownMbps: 1000}, xfer(cf, dn, 220, 5, 20), xfer(cf, up, 40, 5, 20))
			},
			wantStatus: StatusDegraded, wantHead: "slow-download-plan", wantOwner: OwnerWiFi,
		},
		{
			name: "fast line capped by Wi-Fi link (seen live: 756 Mbps on a 1200 Mbps link)",
			build: func(r *ladder.Results) {
				r.Snapshot.WiFi.TxRateMbps = 1200
				withSpeed(r, speed.Plan{}, xfer(cf, dn, 756, 30, 45), xfer(ml, dn, 731, 22, 31), xfer(ml, up, 627, 16, 23))
			},
			wantStatus: StatusOK, wantFinding: "wifi-caps-speed",
		},
		{
			name: "bufferbloat at the modem",
			build: func(r *ladder.Results) {
				withSpeed(r, speed.Plan{}, xfer(cf, dn, 100, 6, 40), xfer(cf, up, 10, 6, 215))
			},
			wantStatus: StatusDegraded, wantHead: "bufferbloat", wantOwner: OwnerRouter,
		},
		{
			name: "queueing on the Wi-Fi",
			build: func(r *ladder.Results) {
				withSpeed(r, speed.Plan{}, xfer(cf, dn, 100, 110, 130), xfer(cf, up, 20, 8, 25))
			},
			wantStatus: StatusDegraded, wantHead: "bufferbloat", wantOwner: OwnerWiFi,
		},
		{
			name: "providers disagree (seen live: Cloudflare upload throttled)",
			build: func(r *ladder.Results) {
				withSpeed(r, speed.Plan{}, xfer(cf, dn, 300, 5, 20), xfer(cf, up, 234, 5, 20), xfer(ml, up, 627, 5, 20))
			},
			wantStatus: StatusOK, wantFinding: "speed-providers-differ-upload",
		},
		{
			name: "upload test failed everywhere",
			build: func(r *ladder.Results) {
				withSpeed(r, speed.Plan{}, xfer(cf, dn, 300, 5, 20),
					speed.Transfer{Provider: cf, Direction: up, Err: "HTTP 403"},
					speed.Transfer{Provider: ml, Direction: up, Err: "M-Lab locate: HTTP 429"})
			},
			wantStatus: StatusOK, wantFinding: "speed-unavailable-upload",
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
				top := firstWarn(v.Findings)
				if top.ID != tc.wantHead {
					t.Errorf("headline finding = %q, want %q", top.ID, tc.wantHead)
				}
				if tc.wantOwner != "" && top.Owner != tc.wantOwner {
					t.Errorf("owner = %q, want %q", top.Owner, tc.wantOwner)
				}
			}
			if tc.wantFinding != "" && !hasFinding(v, tc.wantFinding) {
				t.Errorf("missing %q; got %v", tc.wantFinding, findingIDs(v))
			}
			if tc.wantAbsent != "" && hasFinding(v, tc.wantAbsent) {
				t.Errorf("unexpected %q", tc.wantAbsent)
			}
			n := 0
			for _, c := range v.Checks {
				if c.Stage == StageSpeed {
					n++
				}
			}
			if n != 3 {
				t.Errorf("want 3 speed checks, got %d", n)
			}
		})
	}
}

func TestHealthyHeadlineMentionsSpeed(t *testing.T) {
	r := healthy()
	r.Symptom = "slow"
	withSpeed(&r, speed.Plan{}, xfer(speed.ProviderCloudflare, speed.Download, 300, 5, 20), xfer(speed.ProviderCloudflare, speed.Upload, 40, 5, 20))
	v := Evaluate(r)
	if !strings.Contains(v.Headline, "speed") || !strings.Contains(strings.Join(v.Evidence, " "), "Download 300 Mbps") {
		t.Errorf("headline %q evidence %v", v.Headline, v.Evidence)
	}
	if hasFinding(v, "scope-bandwidth") {
		t.Error("no 'speed not measured' note when it was measured")
	}
}

func TestFailedProviderShownInCheck(t *testing.T) {
	r := healthy()
	withSpeed(&r, speed.Plan{},
		speed.Transfer{Provider: speed.ProviderCloudflare, Direction: speed.Download, Err: speed.RateLimited + " (too many tests)"},
		xfer(speed.ProviderMLab, speed.Download, 689, 5, 20), xfer(speed.ProviderMLab, speed.Upload, 620, 5, 20))
	for _, c := range Evaluate(r).Checks {
		if c.Name == "Download" && c.Detail != "689 Mbps · Cloudflare rate-limited · M-Lab NDT7 689" {
			t.Errorf("download check detail = %q", c.Detail)
		}
	}
}

func TestBloatGrades(t *testing.T) {
	for rise, want := range map[float64]string{2: "A+", 20: "A", 45: "B", 150: "C", 300: "D", 800: "F"} {
		if g := BloatGrade(rise); g != want {
			t.Errorf("BloatGrade(%v) = %s, want %s", rise, g, want)
		}
	}
}
