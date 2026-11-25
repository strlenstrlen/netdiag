package verdict

import (
	"strings"
	"testing"

	"github.com/strlenstrlen/netdiag/internal/ladder"
	"github.com/strlenstrlen/netdiag/internal/probe"
	"github.com/strlenstrlen/netdiag/internal/snapshot"
)

// healthy returns results from a working home Wi-Fi network. Each scenario
// below breaks one thing and checks the diagnosis.
func healthy() ladder.Results {
	ping := func(t string, rtts ...float64) probe.PingResult {
		return probe.PingResult{Target: t, Sent: len(rtts), Received: len(rtts), RTTsMs: rtts}
	}
	dns := func(server, name string) probe.DNSResult {
		return probe.DNSResult{Server: server, Name: name, OK: true, Addrs: []string{"192.0.2.1"}, RTTMs: 20}
	}
	names := []string{"a.example", "b.example", "c.example"}
	r := ladder.Results{
		Snapshot: snapshot.Snapshot{
			Interfaces: []snapshot.Interface{
				{Name: "lo0", Kind: snapshot.KindLoopback, Up: true, IPv4: []string{"127.0.0.1"}},
				{Name: "en0", Kind: snapshot.KindWiFi, Up: true, Running: true, IPv4: []string{"192.168.1.20"}},
			},
			PrimaryInterface: "en0",
			DefaultRoute:     &snapshot.Route{Gateway: "192.168.1.1", Interface: "en0"},
			DNSServers:       []string{"192.168.1.1"},
			WiFi: &snapshot.WiFi{Interface: "en0", PowerOn: true, Associated: true, SignalKnown: true,
				RSSI: -50, Noise: -92, Channel: 36, Band: "5 GHz"},
		},
		GatewayTested: true,
		GatewayPing:   ping("192.168.1.1", 3, 4, 3, 5, 4),
		GatewayTCP: []probe.TCPResult{
			{Target: "192.168.1.1:53", Connected: true},
			{Target: "192.168.1.1:80", Connected: true},
			{Target: "192.168.1.1:443", Refused: true},
		},
		InternetPing: []probe.PingResult{ping("1.1.1.1", 12, 13, 12, 14), ping("8.8.8.8", 15, 15, 16, 15), ping("9.9.9.9", 20, 21, 20, 22)},
		InternetTCP: []probe.TCPResult{
			{Target: "1.1.1.1:443", Connected: true}, {Target: "8.8.8.8:443", Connected: true}, {Target: "9.9.9.9:443", Connected: true},
		},
		Captive: []probe.CaptiveResult{
			{URL: "http://captive.example/a", Reached: true, Expected: true, Status: 200},
			{URL: "http://captive.example/b", Reached: true, Expected: true, Status: 204},
		},
		HTTPS: []probe.HTTPSResult{
			{URL: "https://a.example/", OK: true, Status: 204},
			{URL: "https://b.example/", OK: true, Status: 200},
			{URL: "https://1.1.1.1/", ByIP: true, OK: true, Status: 200},
		},
		ClockSkewKnown: true,
	}
	for _, n := range names {
		r.DNSSystem = append(r.DNSSystem, dns("system", n))
		r.DNSConfigured = append(r.DNSConfigured, dns("192.168.1.1", n))
		for _, s := range []string{"1.1.1.1", "8.8.8.8"} {
			r.DNSPublic = append(r.DNSPublic, dns(s, n))
		}
	}
	return r
}

func failPing(p *probe.PingResult) { p.Received, p.RTTsMs = 0, nil }

func failTCP(ts []probe.TCPResult) {
	for i := range ts {
		ts[i].Connected, ts[i].Refused, ts[i].ErrKind = false, false, "timeout"
	}
}

func failDNS(ds []probe.DNSResult) {
	for i := range ds {
		ds[i].OK, ds[i].Addrs, ds[i].ErrKind = false, nil, "dns-timeout"
	}
}

func failHTTPS(hs []probe.HTTPSResult, kind string) {
	for i := range hs {
		hs[i].OK, hs[i].Status, hs[i].ErrKind = false, 0, kind
	}
}

func killInternet(r *ladder.Results) {
	for i := range r.InternetPing {
		failPing(&r.InternetPing[i])
	}
	failTCP(r.InternetTCP)
	failDNS(r.DNSSystem)
	failDNS(r.DNSConfigured)
	failDNS(r.DNSPublic)
	failHTTPS(r.HTTPS, "timeout")
	for i := range r.Captive {
		r.Captive[i] = probe.CaptiveResult{URL: r.Captive[i].URL, ErrKind: "timeout"}
	}
	r.ClockSkewKnown = false
}

func findingIDs(v Verdict) []string {
	var ids []string
	for _, f := range v.Findings {
		ids = append(ids, f.ID)
	}
	return ids
}

func hasFinding(v Verdict, id string) bool {
	for _, f := range v.Findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestScenarios(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(r *ladder.Results)
		wantStatus  Status
		wantPrimary string // primary finding ID; "" for none
		wantOwner   string
		wantFinding string // a secondary finding that must be present
	}{
		{
			name:       "healthy network",
			mutate:     func(r *ladder.Results) {},
			wantStatus: StatusOK,
		},
		{
			name: "wifi turned off",
			mutate: func(r *ladder.Results) {
				r.Snapshot.Interfaces[1].IPv4 = nil
				r.Snapshot.Interfaces[1].Up = false
				r.Snapshot.WiFi = &snapshot.WiFi{Interface: "en0", PowerOn: false}
				r.Snapshot.DefaultRoute = nil
				r.GatewayTested = false
				killInternet(r)
			},
			wantStatus: StatusFail, wantPrimary: "wifi-off", wantOwner: OwnerUser,
		},
		{
			name: "wifi on, not joined",
			mutate: func(r *ladder.Results) {
				r.Snapshot.Interfaces[1].IPv4 = nil
				r.Snapshot.WiFi = &snapshot.WiFi{Interface: "en0", PowerOn: true}
				r.Snapshot.DefaultRoute = nil
				r.GatewayTested = false
				killInternet(r)
			},
			wantStatus: StatusFail, wantPrimary: "wifi-not-joined",
		},
		{
			name: "DHCP failure: self-assigned address",
			mutate: func(r *ladder.Results) {
				r.Snapshot.Interfaces[1].IPv4 = []string{"169.254.33.7"}
				r.Snapshot.DefaultRoute = nil
				r.GatewayTested = false
				killInternet(r)
			},
			wantStatus: StatusFail, wantPrimary: "dhcp-failed", wantOwner: OwnerRouter,
		},
		{
			name: "no default route",
			mutate: func(r *ladder.Results) {
				r.Snapshot.DefaultRoute = nil
				r.GatewayTested = false
				killInternet(r)
			},
			wantStatus: StatusFail, wantPrimary: "no-route",
		},
		{
			name: "captive portal",
			mutate: func(r *ladder.Results) {
				killInternet(r)
				r.Captive[0] = probe.CaptiveResult{URL: r.Captive[0].URL, Reached: true, Portal: true, Status: 302, Location: "http://login.hotel.example/"}
				r.Captive[1] = probe.CaptiveResult{URL: r.Captive[1].URL, Reached: true, Portal: true, Status: 200}
			},
			wantStatus: StatusFail, wantPrimary: "captive-portal", wantOwner: OwnerUser,
		},
		{
			name: "router unreachable",
			mutate: func(r *ladder.Results) {
				failPing(&r.GatewayPing)
				failTCP(r.GatewayTCP)
				killInternet(r)
			},
			wantStatus: StatusFail, wantPrimary: "router-unreachable", wantOwner: OwnerWiFi,
		},
		{
			name: "ISP outage: router fine, internet dead",
			mutate: func(r *ladder.Results) {
				killInternet(r)
			},
			wantStatus: StatusFail, wantPrimary: "internet-down", wantOwner: OwnerISP,
		},
		{
			name: "internet dead through full-tunnel VPN",
			mutate: func(r *ladder.Results) {
				killInternet(r)
				r.Snapshot.VPN = snapshot.VPNInfo{Active: true, Interfaces: []string{"utun4"}, DefaultRouteViaVPN: true}
			},
			wantStatus: StatusFail, wantPrimary: "internet-down", wantOwner: OwnerAdmin, wantFinding: "vpn-active",
		},
		{
			name: "router DNS down, public DNS works",
			mutate: func(r *ladder.Results) {
				failDNS(r.DNSSystem)
				failDNS(r.DNSConfigured)
				failHTTPS(r.HTTPS[:2], "dns")
			},
			wantStatus: StatusFail, wantPrimary: "dns-configured-down", wantOwner: OwnerDNS,
		},
		{
			name: "all DNS blocked",
			mutate: func(r *ladder.Results) {
				failDNS(r.DNSSystem)
				failDNS(r.DNSConfigured)
				failDNS(r.DNSPublic)
				failHTTPS(r.HTTPS[:2], "dns")
			},
			wantStatus: StatusFail, wantPrimary: "dns-blocked",
		},
		{
			name: "TLS interception",
			mutate: func(r *ladder.Results) {
				failHTTPS(r.HTTPS, "tls-untrusted")
				r.HTTPS[0].Issuer = "Contoso Web Filter CA"
			},
			wantStatus: StatusFail, wantPrimary: "tls-intercepted", wantOwner: OwnerSecurity,
		},
		{
			name: "clock off by days breaks TLS",
			mutate: func(r *ladder.Results) {
				failHTTPS(r.HTTPS, "tls-expired")
				r.ClockSkewSec = 5 * 86400
			},
			wantStatus: StatusFail, wantPrimary: "clock-wrong", wantOwner: OwnerUser,
		},
		{
			name: "HTTPS blocked, TCP works",
			mutate: func(r *ladder.Results) {
				failHTTPS(r.HTTPS, "reset")
			},
			wantStatus: StatusFail, wantPrimary: "https-blocked",
		},
		{
			name: "weak wifi only",
			mutate: func(r *ladder.Results) {
				r.Snapshot.WiFi.RSSI = -79
			},
			wantStatus: StatusDegraded, wantFinding: "wifi-weak",
		},
		{
			name: "router answers TCP but not ping",
			mutate: func(r *ladder.Results) {
				failPing(&r.GatewayPing)
			},
			wantStatus: StatusOK, wantFinding: "gateway-no-ping",
		},
		{
			name: "network blocks ICMP",
			mutate: func(r *ladder.Results) {
				for i := range r.InternetPing {
					failPing(&r.InternetPing[i])
				}
			},
			wantStatus: StatusOK, wantFinding: "icmp-blocked",
		},
		{
			name: "one configured DNS server dead",
			mutate: func(r *ladder.Results) {
				r.Snapshot.DNSServers = append(r.Snapshot.DNSServers, "203.0.113.53")
				for _, n := range []string{"a.example", "b.example", "c.example"} {
					r.DNSConfigured = append(r.DNSConfigured, probe.DNSResult{Server: "203.0.113.53", Name: n, ErrKind: "dns-timeout"})
				}
			},
			wantStatus: StatusDegraded, wantFinding: "dns-server-down",
		},
		{
			name: "packet loss beyond router",
			mutate: func(r *ladder.Results) {
				for i := range r.InternetPing {
					r.InternetPing[i].Received, r.InternetPing[i].RTTsMs = 2, []float64{12, 13}
				}
			},
			wantStatus: StatusDegraded, wantFinding: "isp-loss",
		},
		{
			name: "wifi spikes are info, not a warning",
			mutate: func(r *ladder.Results) {
				r.GatewayPing.RTTsMs = []float64{4, 118, 5, 6, 4}
			},
			wantStatus: StatusOK, wantFinding: "gateway-spikes",
		},
		{
			name: "broken IPv6",
			mutate: func(r *ladder.Results) {
				r.IPv6Tested = true
				r.InternetPing6 = []probe.PingResult{{Target: "2001:db8::1", Sent: 4}}
				r.InternetTCP6 = []probe.TCPResult{{Target: "[2001:db8::1]:443", ErrKind: "timeout"}}
			},
			wantStatus: StatusDegraded, wantFinding: "ipv6-broken",
		},
		{
			name: "single odd captive answer is not a portal",
			mutate: func(r *ladder.Results) {
				r.Captive[0] = probe.CaptiveResult{URL: r.Captive[0].URL, Reached: true, Portal: true, Status: 200}
			},
			wantStatus: StatusOK, wantFinding: "captive-mismatch",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := healthy()
			tc.mutate(&r)
			v := Evaluate(r)
			if v.Status != tc.wantStatus {
				t.Errorf("status = %s, want %s (headline %q, findings %v)", v.Status, tc.wantStatus, v.Headline, findingIDs(v))
			}
			gotPrimary := ""
			if v.Primary != nil {
				gotPrimary = v.Primary.ID
			}
			if gotPrimary != tc.wantPrimary {
				t.Errorf("primary = %q, want %q (headline %q)", gotPrimary, tc.wantPrimary, v.Headline)
			}
			if tc.wantOwner != "" && v.Owner != tc.wantOwner {
				t.Errorf("owner = %q, want %q", v.Owner, tc.wantOwner)
			}
			if tc.wantFinding != "" && !hasFinding(v, tc.wantFinding) {
				t.Errorf("missing finding %q; got %v", tc.wantFinding, findingIDs(v))
			}
			if v.Headline == "" || len(v.Checks) == 0 {
				t.Errorf("empty headline or checks")
			}
			if v.Status == StatusFail && len(v.NextSteps) == 0 {
				t.Errorf("failure verdict without next steps")
			}
		})
	}
}

func TestInterceptionShowsIssuer(t *testing.T) {
	r := healthy()
	failHTTPS(r.HTTPS, "tls-untrusted")
	r.HTTPS[1].Issuer = "Contoso Web Filter CA"
	v := Evaluate(r)
	if !strings.Contains(strings.Join(v.Evidence, " "), "Contoso") {
		t.Errorf("evidence should name the intercepting issuer: %v", v.Evidence)
	}
}

func TestSlowSymptomAddsScopeNote(t *testing.T) {
	r := healthy()
	r.Symptom = "slow"
	if !hasFinding(Evaluate(r), "scope-bandwidth") {
		t.Error("slow symptom on a healthy network should explain that bandwidth isn't measured yet")
	}
}
