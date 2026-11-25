// Package verdict turns raw measurements into a diagnosis: where the fault
// is, who owns the fix, how confident we are, and what to do next.
//
// The primary verdict is the first rung of the connectivity ladder that
// fails. Secondary findings (weak Wi-Fi, packet loss, VPN present, …) are
// reported alongside it whether or not anything failed.
package verdict

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/strlenstrlen/netdiag/internal/ladder"
	"github.com/strlenstrlen/netdiag/internal/probe"
	"github.com/strlenstrlen/netdiag/internal/snapshot"
	"github.com/strlenstrlen/netdiag/internal/speed"
)

type Status string

const (
	StatusOK       Status = "ok"
	StatusDegraded Status = "degraded"
	StatusFail     Status = "fail"
)

type Severity string

const (
	SevInfo Severity = "info"
	SevWarn Severity = "warn"
	SevFail Severity = "fail"
)

// Who should act on a finding.
const (
	OwnerUser     = "You (this computer)"
	OwnerWiFi     = "Wi-Fi / local network"
	OwnerRouter   = "Router / local network"
	OwnerISP      = "Internet provider (ISP)"
	OwnerDNS      = "DNS provider (router or ISP)"
	OwnerAdmin    = "Network admin / IT"
	OwnerSecurity = "Network admin / security software"
	OwnerNetwork  = "The network you're on"
	OwnerNone     = ""
)

type Finding struct {
	ID         string   `json:"id"`
	Severity   Severity `json:"severity"`
	Impact     int      `json:"impact,omitempty"` // ranks warnings; the highest becomes the headline
	Title      string   `json:"title"`
	Owner      string   `json:"owner,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
	NextSteps  []string `json:"next_steps,omitempty"`
}

type CheckStatus string

const (
	CheckPass CheckStatus = "pass"
	CheckWarn CheckStatus = "warn"
	CheckFail CheckStatus = "fail"
	CheckSkip CheckStatus = "skip"
)

// Check stages, shown as separate groups.
const (
	StageConnectivity   = "connectivity"
	StageResponsiveness = "responsiveness"
	StageSpeed          = "speed"
)

type Check struct {
	Stage  string      `json:"stage"`
	Name   string      `json:"name"`
	Status CheckStatus `json:"status"`
	Detail string      `json:"detail"`
}

type Verdict struct {
	Status     Status    `json:"status"`
	Headline   string    `json:"headline"`
	Owner      string    `json:"owner,omitempty"`
	Confidence string    `json:"confidence,omitempty"`
	Evidence   []string  `json:"evidence,omitempty"`
	NextSteps  []string  `json:"next_steps,omitempty"`
	Primary    *Finding  `json:"primary,omitempty"`
	Findings   []Finding `json:"findings,omitempty"`
	Checks     []Check   `json:"checks"`
}

// facts are derived once from the raw results so rules read cleanly.
type facts struct {
	r            ladder.Results
	usable       []snapshot.Interface
	primaryIface *snapshot.Interface
	selfAssigned bool
	wifi         *snapshot.WiFi

	hasRoute      bool
	gwICMP        bool
	gwTCP         bool
	gwAlive       bool
	icmpBlockedOS bool // OS refused unprivileged ICMP
	inetICMP      int  // targets answering ping
	inetTCP       int  // targets accepting TCP 443
	httpsOK       int
	httpsByIPOK   bool
	captiveOK     int // known answer received
	captivePortal *probe.CaptiveResult
	inetAlive     bool

	dnsSysOK, dnsSysTotal int
	dnsPubOK, dnsPubTotal int
	dnsPubServersOK       int
}

func derive(r ladder.Results) facts {
	f := facts{r: r, wifi: r.Snapshot.WiFi}
	anySelf := false
	for i, it := range r.Snapshot.Interfaces {
		if it.Usable() {
			f.usable = append(f.usable, it)
		}
		if it.Up && it.Kind != snapshot.KindLoopback && it.SelfAssignedOnly() {
			anySelf = true
		}
		if it.Name == r.Snapshot.PrimaryInterface {
			f.primaryIface = &r.Snapshot.Interfaces[i]
		}
	}
	f.selfAssigned = anySelf && len(f.usable) == 0

	f.hasRoute = r.Snapshot.DefaultRoute != nil || r.Snapshot.DefaultRoute6 != nil
	f.gwICMP = r.GatewayPing.OK()
	for _, t := range r.GatewayTCP {
		if t.HostAlive() {
			f.gwTCP = true
		}
	}
	f.gwAlive = f.gwICMP || f.gwTCP

	unavailable := 0
	for _, p := range r.InternetPing {
		if p.OK() {
			f.inetICMP++
		}
		if p.Unavailable {
			unavailable++
		}
	}
	f.icmpBlockedOS = unavailable > 0 && unavailable == len(r.InternetPing)
	for _, t := range r.InternetTCP {
		if t.Connected { // a refusal from the internet may be a middlebox; only count real connects
			f.inetTCP++
		}
	}
	for _, h := range r.HTTPS {
		if h.OK {
			f.httpsOK++
			if h.ByIP {
				f.httpsByIPOK = true
			}
		}
	}
	for i, c := range r.Captive {
		if c.Expected {
			f.captiveOK++
		}
		if c.Portal && f.captivePortal == nil {
			f.captivePortal = &r.Captive[i]
		}
	}

	pubServers := map[string]bool{}
	for _, d := range r.DNSSystem {
		f.dnsSysTotal++
		if d.OK {
			f.dnsSysOK++
		}
	}
	for _, d := range r.DNSPublic {
		f.dnsPubTotal++
		if d.OK {
			f.dnsPubOK++
			pubServers[d.Server] = true
		}
	}
	f.dnsPubServersOK = len(pubServers)

	f.inetAlive = f.inetICMP > 0 || f.inetTCP > 0 || f.httpsOK > 0 || f.captiveOK > 0 || f.dnsPubOK > 0
	return f
}

// portalConfirmed: a captive portal is only declared when no check got the
// known answer. One odd response with others fine is more likely a CDN quirk.
func (f facts) portalConfirmed() bool {
	return f.captivePortal != nil && f.captiveOK == 0
}

func Evaluate(r ladder.Results) Verdict {
	f := derive(r)
	findings := append(append(secondary(f), qualityFindings(f)...), speedFindings(f)...)
	sortFindings(findings)
	cs := append(checks(f), qualityChecks(f, findings)...)
	v := Verdict{Findings: findings, Checks: append(cs, speedChecks(f, findings)...)}
	v.Primary = primary(f)

	warns := 0
	for _, x := range v.Findings {
		if x.Severity == SevWarn {
			warns++
		}
	}
	switch {
	case v.Primary != nil:
		v.Status = StatusFail
		v.Headline = v.Primary.Title
		v.Owner = v.Primary.Owner
		v.Confidence = v.Primary.Confidence
		v.Evidence = v.Primary.Evidence
		v.NextSteps = v.Primary.NextSteps
	case warns > 0:
		v.Status = StatusDegraded
		top := firstWarn(v.Findings)
		v.Headline = fmt.Sprintf("Connected, but %s", lowerFirst(top.Title))
		if warns > 1 {
			v.Headline += fmt.Sprintf(" (+%d more %s)", warns-1, plural(warns-1, "issue", "issues"))
		}
		v.Owner = top.Owner
		v.Confidence = top.Confidence
		v.Evidence = top.Evidence
		v.NextSteps = top.NextSteps
	default:
		v.Status = StatusOK
		v.Headline = "No connectivity problems found"
		v.Confidence = "high"
		v.Evidence = []string{
			"Router, internet, DNS and secure websites all responded normally",
		}
		if q := r.Quality; q != nil {
			v.Headline = "No connectivity or responsiveness problems found"
			in := q.InternetStats()
			v.Evidence = append(v.Evidence, fmt.Sprintf(
				"Latency stayed steady for %d seconds: %.0f ms to the internet, %.1f%% packet loss",
				q.SeriesSeconds, in.P50Ms, in.LossPct))
		}
		if s := r.Speed; s != nil {
			if d, u := s.Best(speed.Download), s.Best(speed.Upload); d != nil && u != nil {
				v.Headline = "No connectivity, responsiveness or speed problems found"
				v.Evidence = append(v.Evidence, fmt.Sprintf("Download %.0f Mbps, upload %.0f Mbps", d.Mbps, u.Mbps))
			}
		}
	}
	v.Findings = append(v.Findings, scopeNotes(r, v.Status)...)
	return v
}

// scopeNotes explains what this run did not test, when that matters for the
// reported symptom.
func scopeNotes(r ladder.Results, st Status) []Finding {
	if st == StatusFail {
		return nil
	}
	var out []Finding
	sym := fmt.Sprintf("Reported problem: %s", SymptomLabel(r.Symptom))
	if r.Quality == nil && r.QualitySkipped != "" && symptomNeedsQuality(r.Symptom) {
		out = append(out, Finding{ID: "scope-quality-skipped", Severity: SevInfo,
			Title:     "Responsiveness tests were skipped (" + r.QualitySkipped + ")",
			Evidence:  []string{sym},
			NextSteps: []string{"Run netdiag without --quick to measure lag, DNS speed and page-load timing"}})
	}
	if r.Symptom == "slow" && r.Speed == nil {
		why := "skipped"
		if r.SpeedSkipped != "" {
			why = "skipped (" + r.SpeedSkipped + ")"
		}
		out = append(out, Finding{ID: "scope-bandwidth", Severity: SevInfo,
			Title:     "Download and upload speed weren't measured: " + why,
			Evidence:  []string{sym},
			NextSteps: []string{"Run netdiag without --quick or --no-speed to include the speed test"}})
	}
	if r.Symptom == "drops" {
		out = append(out, Finding{ID: "scope-drops", Severity: SevInfo,
			Title:     "Drops that come and go may not show up in a single run",
			Evidence:  []string{sym},
			NextSteps: []string{"Run netdiag again while the connection is dropping"}})
	}
	return out
}

// ShouldRunQuality says whether stage 2 can produce meaningful results.
func ShouldRunQuality(r ladder.Results) (bool, string) {
	f := derive(r)
	switch {
	case f.portalConfirmed():
		return false, "sign-in page blocks the internet"
	case !f.inetAlive:
		return false, "no internet connectivity"
	}
	return true, ""
}

// sortFindings puts warnings before notes, most important first.
func sortFindings(fs []Finding) {
	rank := map[Severity]int{SevFail: 0, SevWarn: 1, SevInfo: 2}
	sort.SliceStable(fs, func(i, j int) bool {
		if rank[fs[i].Severity] != rank[fs[j].Severity] {
			return rank[fs[i].Severity] < rank[fs[j].Severity]
		}
		return fs[i].Impact > fs[j].Impact
	})
}

// ---- primary: first failing rung ----

func primary(f facts) *Finding {
	r := f.r

	// Rung 1: a usable network interface.
	if len(f.usable) == 0 {
		switch {
		case f.selfAssigned:
			return &Finding{
				ID: "dhcp-failed", Severity: SevFail, Confidence: "high", Owner: OwnerRouter,
				Title: "The network didn't give this computer an IP address",
				Evidence: []string{
					"Only a self-assigned 169.254.x.x address is present, which means no DHCP server answered",
				},
				NextSteps: []string{
					"Turn Wi-Fi off and on (or unplug and replug the cable) to request a new address",
					"Restart the router",
					"If other devices also can't connect, the router's DHCP service is down",
				},
			}
		case f.wifi != nil && !f.wifi.PowerOn:
			return &Finding{
				ID: "wifi-off", Severity: SevFail, Confidence: "high", Owner: OwnerUser,
				Title:     "Wi-Fi is turned off",
				Evidence:  []string{fmt.Sprintf("Wi-Fi interface %s is powered off and no other network is connected", f.wifi.Interface)},
				NextSteps: []string{"Turn Wi-Fi on, or connect an Ethernet cable"},
			}
		case f.wifi != nil && !f.wifi.Associated:
			return &Finding{
				ID: "wifi-not-joined", Severity: SevFail, Confidence: "high", Owner: OwnerUser,
				Title:    "Wi-Fi is on but not connected to a network",
				Evidence: []string{fmt.Sprintf("Wi-Fi interface %s is not associated with any network", f.wifi.Interface)},
				NextSteps: []string{
					"Choose a network from the Wi-Fi menu",
					"If it won't join, forget the network and re-enter the password",
				},
			}
		default:
			return &Finding{
				ID: "no-interface", Severity: SevFail, Confidence: "high", Owner: OwnerUser,
				Title:    "This computer isn't connected to any network",
				Evidence: []string{"No network interface has a usable IP address"},
				NextSteps: []string{
					"Connect to Wi-Fi or plug in an Ethernet cable",
					"Check that any USB or Thunderbolt network adapter is attached",
				},
			}
		}
	}

	// Rung 2: a default route.
	if !f.hasRoute && !f.inetAlive {
		return &Finding{
			ID: "no-route", Severity: SevFail, Confidence: "high", Owner: OwnerRouter,
			Title: "No default gateway: this computer has no route to the internet",
			Evidence: []string{
				fmt.Sprintf("Connected via %s but no default route is configured", ifaceList(f.usable)),
			},
			NextSteps: []string{
				"Reconnect to the network to get fresh settings",
				"If the address was set manually, add the router's address as the gateway",
			},
		}
	}

	// Rung 3: captive portal (checked before reachability, because portals
	// often block everything else and would look like an outage).
	if f.portalConfirmed() {
		ev := []string{fmt.Sprintf("%s returned HTTP %d instead of its known answer", f.captivePortal.URL, f.captivePortal.Status)}
		if f.captivePortal.Location != "" {
			ev = append(ev, "Redirected to "+f.captivePortal.Location)
		}
		return &Finding{
			ID: "captive-portal", Severity: SevFail, Confidence: "high", Owner: OwnerUser,
			Title:    "This network requires you to sign in or accept terms",
			Evidence: ev,
			NextSteps: []string{
				"Open a browser and go to any http:// site (for example http://neverssl.com) to bring up the sign-in page",
				"Complete the sign-in, then run netdiag again",
			},
		}
	}

	// Rung 4: the internet, by IP address.
	if !f.inetAlive {
		inetEv := fmt.Sprintf("None of %d public addresses answered (ping, TCP 443 and HTTPS by IP all failed)", len(r.InternetTCP))
		vpnNote := ""
		if r.Snapshot.VPN.DefaultRouteViaVPN {
			vpnNote = "All traffic is routed through a VPN, so the VPN may be the break point"
		}
		switch {
		case r.GatewayTested && !f.gwAlive:
			ev := []string{
				fmt.Sprintf("Router %s didn't answer ping or TCP connections", r.Snapshot.DefaultRoute.Gateway),
				inetEv,
			}
			if w := f.wifi; w != nil && w.SignalKnown && isWeakSignal(*w) {
				ev = append(ev, fmt.Sprintf("Wi-Fi signal is weak (%d dBm, SNR %d dB)", w.RSSI, w.SNR()))
			}
			if vpnNote != "" {
				ev = append(ev, vpnNote)
			}
			return &Finding{
				ID: "router-unreachable", Severity: SevFail, Confidence: "high", Owner: OwnerWiFi,
				Title:    "Can't reach your router",
				Evidence: ev,
				NextSteps: []string{
					"Check that you're on the right Wi-Fi network, or that the cable is firmly connected",
					"Move closer to the router, or turn Wi-Fi off and on",
					"Restart the router",
					"If other devices on the same network also fail, the router is the problem",
				},
			}
		case r.GatewayTested && f.gwAlive:
			ev := []string{
				fmt.Sprintf("Router %s is reachable (%s)", r.Snapshot.DefaultRoute.Gateway, gatewaySummary(r)),
				inetEv,
			}
			steps := []string{
				"Check the modem's status lights for a lost connection",
				"Restart the modem, wait two minutes, then restart the router",
				"Check your internet provider's outage page from a phone on mobile data",
				"If it persists, contact your internet provider",
			}
			owner := OwnerISP
			if vpnNote != "" {
				ev = append(ev, vpnNote)
				steps = append([]string{"Disconnect the VPN and run netdiag again"}, steps...)
				owner = OwnerAdmin
			}
			return &Finding{
				ID: "internet-down", Severity: SevFail, Confidence: "high", Owner: owner,
				Title:     "Your router is reachable, but the internet isn't",
				Evidence:  ev,
				NextSteps: steps,
			}
		default:
			return &Finding{
				ID: "internet-down", Severity: SevFail, Confidence: "medium", Owner: OwnerNetwork,
				Title:    "No internet connectivity",
				Evidence: []string{inetEv, "The router's address couldn't be determined, so it wasn't tested separately"},
				NextSteps: []string{
					"Reconnect to the network",
					"Restart the router and modem",
				},
			}
		}
	}

	// Rung 5: DNS.
	if f.dnsSysTotal > 0 && f.dnsSysOK == 0 {
		if f.dnsPubOK > 0 {
			return &Finding{
				ID: "dns-configured-down", Severity: SevFail, Confidence: "high", Owner: OwnerDNS,
				Title: "DNS isn't working: your DNS server isn't answering, but public DNS works",
				Evidence: []string{
					fmt.Sprintf("0 of %d lookups succeeded through this computer's resolver (servers: %s)", f.dnsSysTotal, joinOr(r.Snapshot.DNSServers, "unknown")),
					fmt.Sprintf("%d of %d lookups succeeded when asking public DNS directly", f.dnsPubOK, f.dnsPubTotal),
				},
				NextSteps: []string{
					"Restart the router (it is often the DNS server)",
					"As a workaround, set DNS to 1.1.1.1 and 8.8.8.8 in network settings",
					"If it persists, contact whoever runs the network or your internet provider",
				},
			}
		}
		ev := []string{
			fmt.Sprintf("0 of %d lookups succeeded through this computer's resolver", f.dnsSysTotal),
			fmt.Sprintf("Public DNS servers didn't answer either (0 of %d lookups)", f.dnsPubTotal),
		}
		if f.httpsByIPOK || f.inetTCP > 0 {
			ev = append(ev, "Connections by IP address work, so the internet itself is up")
		}
		return &Finding{
			ID: "dns-blocked", Severity: SevFail, Confidence: "medium", Owner: OwnerAdmin,
			Title:    "DNS lookups are failing on this network",
			Evidence: ev,
			NextSteps: []string{
				"Restart the router",
				"This network may block outside DNS; ask its administrator",
			},
		}
	}

	// Rung 6: HTTPS.
	if len(r.HTTPS) > 0 && f.httpsOK == 0 {
		var untrusted, expired *probe.HTTPSResult
		for i, h := range r.HTTPS {
			switch h.ErrKind {
			case "tls-untrusted":
				// Prefer a result that captured the issuer: it names the interceptor.
				if untrusted == nil || (untrusted.Issuer == "" && h.Issuer != "") {
					untrusted = &r.HTTPS[i]
				}
			case "tls-expired":
				expired = &r.HTTPS[i]
			}
		}
		skewBad := r.ClockSkewKnown && math.Abs(r.ClockSkewSec) > 3600
		switch {
		case skewBad || (expired != nil && untrusted == nil):
			ev := []string{"Secure connections fail certificate date checks"}
			if r.ClockSkewKnown {
				ev = append(ev, "This computer's clock is off by "+humanDuration(r.ClockSkewSec))
			}
			return &Finding{
				ID: "clock-wrong", Severity: SevFail, Confidence: confidence(r.ClockSkewKnown), Owner: OwnerUser,
				Title:    "Your computer's clock is wrong, which breaks secure connections",
				Evidence: ev,
				NextSteps: []string{
					"Turn on \"Set time and date automatically\" in Date & Time settings",
				},
			}
		case untrusted != nil:
			ev := []string{"Websites presented certificates this computer doesn't trust"}
			if untrusted.Issuer != "" {
				ev = append(ev, "Certificate issued by: "+untrusted.Issuer)
			}
			return &Finding{
				ID: "tls-intercepted", Severity: SevFail, Confidence: "high", Owner: OwnerSecurity,
				Title:    "Secure connections are being intercepted",
				Evidence: ev,
				NextSteps: []string{
					"Antivirus, a content filter or a corporate proxy is likely inspecting HTTPS traffic",
					"On a work network, ask IT to install their certificate on this computer",
					"On a public network, don't sign in to anything until this is resolved",
				},
			}
		default:
			return &Finding{
				ID: "https-blocked", Severity: SevFail, Confidence: "medium", Owner: OwnerAdmin,
				Title: "Secure websites aren't loading",
				Evidence: []string{
					fmt.Sprintf("0 of %d HTTPS checks succeeded (%s)", len(r.HTTPS), errKinds(r.HTTPS)),
					fmt.Sprintf("Basic internet reachability works (%d of %d hosts accept connections)", f.inetTCP, len(r.InternetTCP)),
				},
				NextSteps: []string{
					"A firewall, filter or security software may be blocking web traffic",
					"Try temporarily disabling security software or VPN and run netdiag again",
				},
			}
		}
	}
	return nil
}

// ---- secondary findings ----

func secondary(f facts) []Finding {
	r := f.r
	var out []Finding
	add := func(x Finding) { out = append(out, x) }

	// Wi-Fi signal.
	if w := f.wifi; w != nil && w.SignalKnown && w.Associated {
		if isWeakSignal(*w) {
			add(Finding{
				ID: "wifi-weak", Severity: SevWarn, Impact: 70, Confidence: "high", Owner: OwnerWiFi,
				Title:    "Weak Wi-Fi signal",
				Evidence: []string{fmt.Sprintf("Signal %d dBm, noise %d dBm, SNR %d dB (want better than -67 dBm and 25 dB)", w.RSSI, w.Noise, w.SNR())},
				NextSteps: []string{
					"Move closer to the router or remove obstacles between you",
					"Prefer the 5 GHz or 6 GHz network if one is available",
					"Consider a mesh node or access point for this area",
				},
			})
		}
		if w.Band == "2.4 GHz" {
			add(Finding{
				ID: "wifi-24ghz", Severity: SevInfo, Owner: OwnerWiFi,
				Title:    "Connected on 2.4 GHz Wi-Fi, which is slower and more crowded",
				Evidence: []string{fmt.Sprintf("Channel %d, %s", w.Channel, w.Band)},
			})
		}
	}

	// Router quality (rough 5-ping estimate; stage 2 replaces it when it runs).
	if r.Quality == nil && r.GatewayTested && r.GatewayPing.OK() && r.GatewayPing.Sent >= 3 {
		gp := r.GatewayPing
		if gp.LossPct() >= 20 {
			add(Finding{
				ID: "gateway-loss", Severity: SevWarn, Impact: 80, Confidence: "medium", Owner: OwnerWiFi,
				Title: "Packet loss between this computer and the router",
				Evidence: []string{
					fmt.Sprintf("%d of %d pings to the router were lost (%.0f%%)", gp.Sent-gp.Received, gp.Sent, gp.LossPct()),
					"Loss this close to you usually means Wi-Fi interference or a bad cable",
				},
				NextSteps: []string{"Move closer to the router or try a wired connection to compare"},
			})
		}
		// Median, not average: Wi-Fi power-saving and channel contention
		// cause brief spikes that inflate the average on healthy networks.
		med := probe.Median(gp.RTTsMs)
		switch {
		case med > 30:
			add(Finding{
				ID: "gateway-slow", Severity: SevWarn, Impact: 60, Confidence: "medium", Owner: OwnerWiFi,
				Title:    "Slow responses from the router",
				Evidence: []string{fmt.Sprintf("Router replies took %.0f ms (median, max %.0f ms); a healthy local network is under 10 ms", med, gp.MaxMs())},
				NextSteps: []string{
					"Wi-Fi congestion or a busy router; try closer to the router or a wired connection",
				},
			})
		case gp.MaxMs() > 50 && gp.MaxMs() > 4*med:
			add(Finding{
				ID: "gateway-spikes", Severity: SevInfo, Owner: OwnerWiFi,
				Title:    "Occasional latency spikes on the local network",
				Evidence: []string{fmt.Sprintf("Router replies are usually %.0f ms but spiked to %.0f ms; common on Wi-Fi, noticeable on video calls if frequent", med, gp.MaxMs())},
			})
		}
	}

	// Loss beyond the router (only meaningful if the router itself is clean).
	if r.Quality == nil && r.GatewayPing.OK() && r.GatewayPing.LossPct() == 0 {
		lossy := 0
		var ev []string
		for _, p := range r.InternetPing {
			if p.OK() && p.LossPct() >= 25 {
				lossy++
				ev = append(ev, fmt.Sprintf("%s: %.0f%% loss", p.Target, p.LossPct()))
			}
		}
		if lossy >= 2 {
			add(Finding{
				ID: "isp-loss", Severity: SevWarn, Impact: 80, Confidence: "medium", Owner: OwnerISP,
				Title:    "Packet loss beyond your router",
				Evidence: append([]string{"No loss to the router, but loss to multiple internet hosts"}, ev...),
				NextSteps: []string{
					"Restart the modem",
					"If it persists, report packet loss to your internet provider",
				},
			})
		}
	}

	// ICMP handling notes.
	switch {
	case f.icmpBlockedOS:
		add(Finding{ID: "icmp-unavailable", Severity: SevInfo,
			Title:    "Ping tests couldn't run on this system; TCP checks were used instead",
			Evidence: []string{firstErr(r.InternetPing)}})
	case f.inetICMP == 0 && f.inetTCP > 0:
		add(Finding{ID: "icmp-blocked", Severity: SevInfo, Owner: OwnerNetwork,
			Title:    "This network blocks ping; TCP checks were used instead",
			Evidence: []string{fmt.Sprintf("0 of %d hosts answered ping, %d accepted TCP connections", len(r.InternetPing), f.inetTCP)}})
	}
	if r.GatewayTested && !f.gwICMP && f.gwTCP && !f.icmpBlockedOS {
		add(Finding{ID: "gateway-no-ping", Severity: SevInfo,
			Title:    "Your router doesn't answer ping (normal for some routers)",
			Evidence: []string{"It did answer on a TCP port, so it is reachable"}})
	}

	// DNS details (only when DNS isn't already the primary failure).
	if f.dnsSysOK > 0 && f.dnsSysOK < f.dnsSysTotal {
		var failed []string
		for _, d := range r.DNSSystem {
			if !d.OK {
				failed = append(failed, d.Name)
			}
		}
		add(Finding{
			ID: "dns-partial", Severity: SevWarn, Impact: 55, Confidence: "medium", Owner: OwnerDNS,
			Title:     "Some DNS lookups failed",
			Evidence:  []string{fmt.Sprintf("%d of %d names resolved; failed: %s", f.dnsSysOK, f.dnsSysTotal, strings.Join(failed, ", "))},
			NextSteps: []string{"Run netdiag again; if it repeats, try public DNS (1.1.1.1, 8.8.8.8)"},
		})
	}
	if f.dnsSysOK > 0 {
		for _, s := range r.Snapshot.DNSServers {
			ok, total := 0, 0
			for _, d := range r.DNSConfigured {
				if d.Server == s {
					total++
					if d.OK {
						ok++
					}
				}
			}
			if total > 0 && ok == 0 {
				add(Finding{
					ID: "dns-server-down", Severity: SevWarn, Impact: 50, Confidence: "high", Owner: OwnerDNS,
					Title: fmt.Sprintf("DNS server %s isn't responding", s),
					Evidence: []string{
						fmt.Sprintf("0 of %d direct queries to %s succeeded (%s)", total, s, dnsErrKinds(r.DNSConfigured, s)),
						"Other DNS servers are covering for it, but lookups can stall while it times out",
					},
					NextSteps: []string{"Remove it from DNS settings, or have the network owner fix it"},
				})
			}
		}
		var sysRTT []float64
		for _, d := range r.DNSSystem {
			if d.OK {
				sysRTT = append(sysRTT, d.RTTMs)
			}
		}
		if med := probe.Median(sysRTT); r.Quality == nil && med > 300 {
			add(Finding{
				ID: "dns-slow", Severity: SevWarn, Impact: 45, Confidence: "medium", Owner: OwnerDNS,
				Title:     "Slow DNS lookups",
				Evidence:  []string{fmt.Sprintf("Lookups took %.0f ms (median); under 50 ms is typical", med)},
				NextSteps: []string{"Try public DNS (1.1.1.1, 8.8.8.8) to see if pages start loading faster"},
			})
		}
	}

	// Partial HTTPS failure.
	if f.httpsOK > 0 && f.httpsOK < len(r.HTTPS) {
		var failed []string
		for _, h := range r.HTTPS {
			if !h.OK {
				failed = append(failed, fmt.Sprintf("%s (%s)", h.URL, nz(h.ErrKind, fmt.Sprintf("HTTP %d", h.Status))))
			}
		}
		add(Finding{
			ID: "https-partial", Severity: SevWarn, Impact: 30, Confidence: "low", Owner: OwnerNetwork,
			Title:    "Some secure test sites didn't load",
			Evidence: []string{fmt.Sprintf("%d of %d succeeded; failed: %s", f.httpsOK, len(r.HTTPS), strings.Join(failed, "; "))},
		})
	}

	// Captive portal check disagreed but wasn't confirmed.
	if f.captivePortal != nil && !f.portalConfirmed() {
		add(Finding{
			ID: "captive-mismatch", Severity: SevInfo,
			Title:    "One connectivity-check URL returned an unexpected answer",
			Evidence: []string{fmt.Sprintf("%s returned HTTP %d; other checks were normal", f.captivePortal.URL, f.captivePortal.Status)},
		})
	}

	// Clock.
	if r.ClockSkewKnown && math.Abs(r.ClockSkewSec) > 120 && math.Abs(r.ClockSkewSec) <= 3600 {
		add(Finding{
			ID: "clock-skew", Severity: SevWarn, Impact: 35, Confidence: "medium", Owner: OwnerUser,
			Title:     "Your computer's clock is off",
			Evidence:  []string{"Off by " + humanDuration(r.ClockSkewSec) + " compared with web servers"},
			NextSteps: []string{"Turn on \"Set time and date automatically\" in Date & Time settings"},
		})
	}

	// IPv6.
	if r.IPv6Tested {
		ok := false
		for _, p := range r.InternetPing6 {
			ok = ok || p.OK()
		}
		for _, t := range r.InternetTCP6 {
			ok = ok || t.Connected
		}
		if !ok && f.inetAlive {
			add(Finding{
				ID: "ipv6-broken", Severity: SevWarn, Impact: 65, Confidence: "high", Owner: OwnerRouter,
				Title: "IPv6 is configured but doesn't work",
				Evidence: []string{
					"This computer has an IPv6 address and route, but no IPv6 host answered",
					"Apps try IPv6 first, so this causes delays before they fall back to IPv4",
				},
				NextSteps: []string{
					"Restart the router",
					"If it persists, disable IPv6 on the router or ask the network owner to fix it",
				},
			})
		}
	}

	// Environment notes.
	if v := r.Snapshot.VPN; v.Active {
		t := "A VPN is connected"
		if v.DefaultRouteViaVPN {
			t = "A VPN is connected and carrying all traffic"
		}
		add(Finding{ID: "vpn-active", Severity: SevInfo, Title: t,
			Evidence: []string{"Results reflect the VPN path. To isolate the local network, disconnect the VPN and run netdiag again. Interfaces: " + strings.Join(v.Interfaces, ", ")}})
	}
	if p := r.Snapshot.Proxy; p.Any() {
		add(Finding{ID: "proxy-configured", Severity: SevInfo,
			Title:    "A proxy is configured; netdiag tested direct connections",
			Evidence: []string{"Apps that use the proxy may behave differently: " + proxySummary(p)}})
	}
	if len(f.usable) > 1 {
		add(Finding{ID: "multi-interface", Severity: SevInfo,
			Title:    "More than one network connection is active",
			Evidence: []string{fmt.Sprintf("%s; traffic uses %s", ifaceList(f.usable), nz(r.Snapshot.PrimaryInterface, "unknown"))}})
	}
	return out
}

// ---- checks table ----

func checks(f facts) []Check {
	r := f.r
	var cs []Check
	add := func(name string, st CheckStatus, detail string) {
		cs = append(cs, Check{Stage: StageConnectivity, Name: name, Status: st, Detail: detail})
	}

	// Connection.
	switch {
	case f.primaryIface != nil && f.primaryIface.Usable():
		add("Network connection", CheckPass, ifaceDesc(*f.primaryIface))
	case len(f.usable) > 0:
		add("Network connection", CheckPass, ifaceDesc(f.usable[0]))
	case f.selfAssigned:
		add("Network connection", CheckFail, "self-assigned address only (no DHCP)")
	default:
		add("Network connection", CheckFail, "not connected")
	}

	// Wi-Fi.
	if w := f.wifi; w != nil && (f.primaryIface == nil || f.primaryIface.Name == w.Interface || len(f.usable) == 0) {
		switch {
		case !w.PowerOn:
			add("Wi-Fi signal", CheckFail, "Wi-Fi is off")
		case !w.Associated:
			add("Wi-Fi signal", CheckFail, "not connected to a network")
		case !w.SignalKnown:
			add("Wi-Fi signal", CheckSkip, "signal strength unavailable")
		default:
			st := CheckPass
			if isWeakSignal(*w) {
				st = CheckWarn
			}
			add("Wi-Fi signal", st, wifiDesc(*w))
		}
	}

	// Router.
	switch {
	case !r.GatewayTested && r.Snapshot.DefaultRoute == nil:
		add("Router", CheckFail, "no default gateway")
	case !r.GatewayTested:
		add("Router", CheckSkip, "gateway "+r.Snapshot.DefaultRoute.Gateway+" isn't an IP address")
	case f.gwICMP:
		st := CheckPass
		if r.GatewayPing.LossPct() >= 20 || probe.Median(r.GatewayPing.RTTsMs) > 30 {
			st = CheckWarn
		}
		add("Router", st, r.Snapshot.DefaultRoute.Gateway+" · "+gatewaySummary(r))
	case f.gwTCP:
		add("Router", CheckPass, r.Snapshot.DefaultRoute.Gateway+" · answers on TCP (no ping)")
	default:
		add("Router", CheckFail, r.Snapshot.DefaultRoute.Gateway+" · no response")
	}

	// Internet.
	reach := 0
	for i := range r.InternetTCP {
		alive := r.InternetTCP[i].Connected
		if i < len(r.InternetPing) && r.InternetPing[i].OK() {
			alive = true
		}
		if alive {
			reach++
		}
	}
	total := max(len(r.InternetTCP), len(r.InternetPing))
	var rtts []float64
	for _, p := range r.InternetPing {
		if p.OK() {
			rtts = append(rtts, probe.Median(p.RTTsMs))
		}
	}
	detail := fmt.Sprintf("%d/%d public hosts reachable", reach, total)
	if len(rtts) > 0 {
		detail += fmt.Sprintf(" · ping %.0f ms", probe.Median(rtts))
	}
	switch {
	case reach == 0 && !f.inetAlive:
		add("Internet", CheckFail, detail)
	case reach < total:
		add("Internet", CheckWarn, detail)
	default:
		add("Internet", CheckPass, detail)
	}

	// DNS.
	var sysRTT []float64
	for _, d := range r.DNSSystem {
		if d.OK {
			sysRTT = append(sysRTT, d.RTTMs)
		}
	}
	dd := fmt.Sprintf("%d/%d names resolved", f.dnsSysOK, f.dnsSysTotal)
	if len(sysRTT) > 0 {
		dd += fmt.Sprintf(" · %.0f ms", probe.Median(sysRTT))
	}
	if len(r.Snapshot.DNSServers) > 0 {
		dd += " · via " + strings.Join(r.Snapshot.DNSServers, ", ")
	}
	add("DNS (this computer)", ratioStatus(f.dnsSysOK, f.dnsSysTotal), dd)
	pubServers := map[string]bool{}
	for _, d := range r.DNSPublic {
		pubServers[d.Server] = true
	}
	add("DNS (public servers)", ratioStatus(f.dnsPubOK, f.dnsPubTotal),
		fmt.Sprintf("%d/%d lookups · %d of %d providers answered", f.dnsPubOK, f.dnsPubTotal, f.dnsPubServersOK, len(pubServers)))

	// Captive portal.
	switch {
	case f.portalConfirmed():
		add("Sign-in page", CheckFail, "captive portal detected")
	case f.captiveOK > 0:
		add("Sign-in page", CheckPass, "none detected")
	default:
		add("Sign-in page", CheckSkip, "couldn't check (no web access)")
	}

	// HTTPS.
	var hRTT []float64
	for _, h := range r.HTTPS {
		if h.OK {
			hRTT = append(hRTT, h.RTTMs)
		}
	}
	hd := fmt.Sprintf("%d/%d sites loaded", f.httpsOK, len(r.HTTPS))
	if len(hRTT) > 0 {
		hd += fmt.Sprintf(" · %.0f ms", probe.Median(hRTT))
	}
	add("Secure websites", ratioStatus(f.httpsOK, len(r.HTTPS)), hd)

	// IPv6.
	if r.IPv6Tested {
		ok := 0
		for _, t := range r.InternetTCP6 {
			if t.Connected {
				ok++
			}
		}
		st := CheckPass
		if ok == 0 {
			st = CheckWarn
		}
		add("IPv6", st, fmt.Sprintf("%d/%d hosts reachable", ok, len(r.InternetTCP6)))
	} else {
		add("IPv6", CheckSkip, "not configured on this network")
	}

	// Clock.
	switch {
	case !r.ClockSkewKnown:
		add("Clock", CheckSkip, "couldn't compare")
	case math.Abs(r.ClockSkewSec) > 120:
		add("Clock", CheckWarn, "off by "+humanDuration(r.ClockSkewSec))
	default:
		add("Clock", CheckPass, "in sync")
	}
	return cs
}

// ---- helpers ----

func isWeakSignal(w snapshot.WiFi) bool {
	if !w.SignalKnown {
		return false
	}
	return w.RSSI < -70 || (w.SNR() > 0 && w.SNR() < 20)
}

func gatewaySummary(r ladder.Results) string {
	gp := r.GatewayPing
	if gp.OK() {
		return fmt.Sprintf("%d/%d ping replies · %.0f ms", gp.Received, gp.Sent, probe.Median(gp.RTTsMs))
	}
	return "answers on TCP"
}

func ifaceDesc(it snapshot.Interface) string {
	kind := map[string]string{snapshot.KindWiFi: "Wi-Fi", snapshot.KindEthernet: "Ethernet", snapshot.KindVPN: "VPN"}[it.Kind]
	addrs := it.RoutableIPv4()
	if len(addrs) == 0 {
		addrs = it.IPv6
	}
	s := it.Name
	if kind != "" {
		s += " (" + kind + ")"
	}
	if len(addrs) > 0 {
		s += " · " + addrs[0]
	}
	return s
}

func ifaceList(its []snapshot.Interface) string {
	var parts []string
	for _, it := range its {
		parts = append(parts, ifaceDesc(it))
	}
	return strings.Join(parts, ", ")
}

func wifiDesc(w snapshot.WiFi) string {
	parts := []string{fmt.Sprintf("%d dBm", w.RSSI)}
	if w.SNR() > 0 {
		parts = append(parts, fmt.Sprintf("SNR %d dB", w.SNR()))
	}
	if w.Band != "" {
		b := w.Band
		if w.Channel > 0 {
			b += fmt.Sprintf(" ch %d", w.Channel)
		}
		parts = append(parts, b)
	}
	if w.PHYMode != "" {
		parts = append(parts, w.PHYMode)
	}
	if w.TxRateMbps > 0 {
		parts = append(parts, fmt.Sprintf("%.0f Mbps link", w.TxRateMbps))
	}
	return strings.Join(parts, " · ")
}

func proxySummary(p snapshot.Proxy) string {
	var parts []string
	if p.HTTP != "" {
		parts = append(parts, "HTTP "+p.HTTP)
	}
	if p.HTTPS != "" {
		parts = append(parts, "HTTPS "+p.HTTPS)
	}
	if p.SOCKS != "" {
		parts = append(parts, "SOCKS "+p.SOCKS)
	}
	if p.PACURL != "" {
		parts = append(parts, "PAC "+p.PACURL)
	}
	if p.AutoDiscovery {
		parts = append(parts, "auto-discovery (WPAD)")
	}
	for k, v := range p.Env {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ", ")
}

func ratioStatus(ok, total int) CheckStatus {
	switch {
	case total == 0:
		return CheckSkip
	case ok == 0:
		return CheckFail
	case ok < total:
		return CheckWarn
	}
	return CheckPass
}

func errKinds(hs []probe.HTTPSResult) string {
	seen := map[string]bool{}
	var out []string
	for _, h := range hs {
		k := nz(h.ErrKind, "other")
		if !h.OK && !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return strings.Join(out, ", ")
}

func dnsErrKinds(ds []probe.DNSResult, server string) string {
	seen := map[string]bool{}
	var out []string
	for _, d := range ds {
		if d.Server == server && !d.OK && !seen[d.ErrKind] {
			seen[d.ErrKind] = true
			out = append(out, nz(d.ErrKind, "no answer"))
		}
	}
	return strings.Join(out, ", ")
}

func firstErr(ps []probe.PingResult) string {
	for _, p := range ps {
		if p.Err != "" {
			return p.Err
		}
	}
	return ""
}

func firstWarn(fs []Finding) Finding {
	for _, f := range fs {
		if f.Severity == SevWarn {
			return f
		}
	}
	return Finding{}
}

func humanDuration(sec float64) string {
	a := math.Abs(sec)
	dir := "behind"
	if sec < 0 {
		dir = "ahead"
	}
	switch {
	case a >= 86400:
		return fmt.Sprintf("%.0f days (%s)", a/86400, dir)
	case a >= 3600:
		return fmt.Sprintf("%.1f hours (%s)", a/3600, dir)
	case a >= 60:
		return fmt.Sprintf("%.0f minutes (%s)", a/60, dir)
	}
	return fmt.Sprintf("%.0f seconds (%s)", a, dir)
}

func confidence(high bool) string {
	if high {
		return "high"
	}
	return "medium"
}

func joinOr(xs []string, def string) string {
	if len(xs) == 0 {
		return def
	}
	return strings.Join(xs, ", ")
}

func nz(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// ---- symptoms ----

var symptoms = []struct{ ID, Label string }{
	{"broken", "Nothing works / can't connect"},
	{"slow", "The internet is slow"},
	{"some-sites", "Some sites or apps don't work"},
	{"drops", "It keeps dropping"},
	{"only-me", "It works for others, but not me"},
}

func Symptoms() []struct{ ID, Label string } { return symptoms }

func SymptomLabel(id string) string {
	for _, s := range symptoms {
		if s.ID == id {
			return s.Label
		}
	}
	return id
}

func ValidSymptom(id string) bool {
	if id == "" {
		return true
	}
	for _, s := range symptoms {
		if s.ID == id {
			return true
		}
	}
	return false
}

func symptomNeedsQuality(id string) bool {
	return id == "slow" || id == "drops"
}
