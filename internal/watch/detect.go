// Package watch monitors the connection continuously and records drops,
// lag and configuration changes as timestamped events with likely causes:
// the answer to "it keeps dropping", which a one-off test can miss.
package watch

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// Tick is one round of probes. A nil latency means no reply.
type Tick struct {
	At     time.Time `json:"t"`
	Router *float64  `json:"router"`
	Inet   *float64  `json:"inet"` // fastest internet reply this tick
}

// State is the slowly changing network configuration, sampled every few seconds.
type State struct {
	At        time.Time `json:"t"`
	Interface string    `json:"interface,omitempty"`
	IPv4      string    `json:"ipv4,omitempty"`
	Gateway   string    `json:"gateway,omitempty"`
	WiFiOn    bool      `json:"wifi_associated,omitempty"`
	WiFiKnown bool      `json:"wifi_known,omitempty"`
	RSSI      int       `json:"rssi,omitempty"`
	Channel   int       `json:"channel,omitempty"`
	VPN       bool      `json:"vpn,omitempty"`
}

// Cause says where a problem happened.
const (
	CauseLocal    = "local"    // router unreachable too: Wi-Fi or local network
	CauseWiFi     = "wifi"     // Wi-Fi disconnected or changed at the time
	CauseUpstream = "upstream" // router fine: modem or provider
	CauseDNS      = "dns"
	CauseConfig   = "config"
)

type Event struct {
	Kind   string    `json:"kind"` // outage, lag, dns, wifi, signal, ip, gateway, vpn
	Start  time.Time `json:"start"`
	End    time.Time `json:"end,omitempty"` // zero while ongoing, or for instant events
	Cause  string    `json:"cause,omitempty"`
	Title  string    `json:"title"`
	Detail string    `json:"detail,omitempty"`
}

func (e Event) Duration() time.Duration {
	if e.End.IsZero() {
		return 0
	}
	return e.End.Sub(e.Start)
}

// Detector turns ticks and states into events. It holds no clock of its
// own, so tests can feed it synthetic timelines.
type Detector struct {
	Events []Event
	// OnEvent is called when an event starts and again when it ends.
	OnEvent func(e Event, ended bool)

	recentInet   []float64 // last 60 internet replies, for the baseline
	recentRouter []float64

	down        int // consecutive ticks with no internet reply
	downSince   time.Time
	downRouter  int // of those, ticks where the router was silent too
	outage      *Event
	outRouter   int // ticks in the current outage where the router was also silent
	outTicks    int
	wifiChanged bool // a Wi-Fi change happened during the current outage or lag

	slow      int // consecutive slow ticks
	slowSince time.Time
	fast      int // consecutive normal ticks while lagging
	lag       *Event
	lagRouter int
	lagTicks  int
	lagPeak   float64

	last *State
}

const (
	outageAfter = 2 // ticks without any internet reply before calling it an outage
	lagAfter    = 3 // consecutive slow ticks before calling it lag
)

func (d *Detector) emit(e *Event, ended bool) {
	if d.OnEvent != nil {
		d.OnEvent(*e, ended)
	}
}

func (d *Detector) add(e Event) {
	d.Events = append(d.Events, e)
	if d.OnEvent != nil {
		d.OnEvent(e, false)
	}
}

func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	return s[len(s)/2]
}

func push(xs []float64, v float64) []float64 {
	xs = append(xs, v)
	if len(xs) > 60 {
		xs = xs[1:]
	}
	return xs
}

// LagThreshold is the internet latency counted as "slow": three times the
// recent median, and never below 150 ms.
func (d *Detector) LagThreshold() float64 { return math.Max(150, 3*median(d.recentInet)) }

func (d *Detector) Tick(t Tick) {
	// Outages.
	if t.Inet == nil {
		if d.down == 0 {
			d.downSince, d.downRouter = t.At, 0
		}
		d.down++
		if t.Router == nil {
			d.downRouter++
		}
		switch {
		case d.down == outageAfter:
			d.outage = &Event{Kind: "outage", Start: d.downSince, Title: "Internet unreachable"}
			d.outRouter, d.outTicks, d.wifiChanged = d.downRouter, d.down, false
			d.closeLag(t.At) // an outage supersedes lag
			d.emit(d.outage, false)
		case d.outage != nil:
			d.outTicks++
			if t.Router == nil {
				d.outRouter++
			}
		}
	} else {
		if d.outage != nil {
			d.outage.End = t.At
			switch {
			case d.wifiChanged:
				d.outage.Cause = CauseWiFi
				d.outage.Detail = "The Wi-Fi connection changed during the outage"
			case d.outTicks > 0 && float64(d.outRouter)/float64(d.outTicks) >= 0.5:
				d.outage.Cause = CauseLocal
				d.outage.Detail = "The router stopped answering too, so the break was on the Wi-Fi or local network"
			default:
				d.outage.Cause = CauseUpstream
				d.outage.Detail = "The router kept answering, so the break was beyond it: modem or internet provider"
			}
			d.outage.Title = fmt.Sprintf("Internet unreachable for %s", human(d.outage.Duration()))
			d.Events = append(d.Events, *d.outage)
			d.emit(d.outage, true)
			d.outage = nil
		}
		d.down = 0

		// Lag, judged against the baseline before this sample joins it.
		thr := d.LagThreshold()
		if len(d.recentInet) >= 10 && *t.Inet > thr {
			if d.slow == 0 {
				d.slowSince = t.At
			}
			d.slow++
			d.fast = 0
			if d.lag == nil && d.slow == lagAfter {
				d.lag = &Event{Kind: "lag", Start: d.slowSince, Title: "High latency"}
				d.lagRouter, d.lagTicks, d.lagPeak, d.wifiChanged = 0, 0, 0, false
				d.emit(d.lag, false)
			}
			if d.lag != nil {
				d.lagTicks++
				d.lagPeak = math.Max(d.lagPeak, *t.Inet)
				rthr := math.Max(100, 3*median(d.recentRouter))
				if t.Router == nil || *t.Router > rthr {
					d.lagRouter++
				}
			}
		} else {
			d.slow = 0
			if d.lag != nil {
				d.fast++
				if d.fast >= 2 {
					d.closeLag(t.At)
				}
			}
			d.recentInet = push(d.recentInet, *t.Inet)
		}
	}
	if t.Router != nil && d.lag == nil {
		d.recentRouter = push(d.recentRouter, *t.Router)
	}
}

func (d *Detector) closeLag(at time.Time) {
	if d.lag == nil {
		return
	}
	d.lag.End = at
	switch {
	case d.wifiChanged:
		d.lag.Cause = CauseWiFi
	case d.lagTicks > 0 && float64(d.lagRouter)/float64(d.lagTicks) >= 0.5:
		d.lag.Cause = CauseLocal
		d.lag.Detail = "The router was slow too, so the delay was on the Wi-Fi or local network"
	default:
		d.lag.Cause = CauseUpstream
		d.lag.Detail = "The router stayed fast, so the delay was beyond it"
	}
	d.lag.Title = fmt.Sprintf("High latency for %s (peak %.0f ms)", human(d.lag.Duration()), d.lagPeak)
	d.Events = append(d.Events, *d.lag)
	d.emit(d.lag, true)
	d.lag, d.slow, d.fast = nil, 0, 0
}

// DNS records one periodic lookup. Failures only count while the internet
// is otherwise up; during an outage they are expected.
func (d *Detector) DNS(at time.Time, ok bool, errKind string) {
	if ok || d.outage != nil || d.down > 0 {
		return
	}
	d.add(Event{Kind: "dns", Start: at, Cause: CauseDNS, Title: "DNS lookup failed while the connection was up", Detail: errKind})
}

// State compares the network configuration with the previous sample.
func (d *Detector) State(s State) {
	p := d.last
	d.last = &s
	if p == nil {
		return
	}
	wifi := func(e Event) {
		e.Cause = CauseWiFi
		d.wifiChanged = true
		d.add(e)
	}
	switch {
	case p.WiFiOn && !s.WiFiOn && s.WiFiKnown:
		wifi(Event{Kind: "wifi", Start: s.At, Title: "Wi-Fi disconnected"})
	case !p.WiFiOn && s.WiFiOn:
		wifi(Event{Kind: "wifi", Start: s.At, Title: "Wi-Fi connected", Detail: fmt.Sprintf("channel %d, %d dBm", s.Channel, s.RSSI)})
	case p.WiFiOn && s.WiFiOn && p.Channel != s.Channel && s.Channel != 0:
		wifi(Event{Kind: "wifi", Start: s.At, Title: fmt.Sprintf("Wi-Fi moved from channel %d to %d", p.Channel, s.Channel),
			Detail: "Roaming to another access point, or the router changed channel"})
	case p.WiFiOn && s.WiFiOn && s.RSSI < -75 && p.RSSI >= -70:
		wifi(Event{Kind: "signal", Start: s.At, Title: fmt.Sprintf("Wi-Fi signal dropped from %d to %d dBm", p.RSSI, s.RSSI)})
	}
	if p.IPv4 != s.IPv4 && (p.IPv4 != "" || s.IPv4 != "") {
		d.add(Event{Kind: "ip", Start: s.At, Cause: CauseConfig, Title: fmt.Sprintf("IP address changed: %s → %s", nz(p.IPv4, "none"), nz(s.IPv4, "none"))})
	}
	if p.Gateway != s.Gateway && (p.Gateway != "" || s.Gateway != "") {
		d.add(Event{Kind: "gateway", Start: s.At, Cause: CauseConfig, Title: fmt.Sprintf("Router (gateway) changed: %s → %s", nz(p.Gateway, "none"), nz(s.Gateway, "none"))})
	}
	if p.VPN != s.VPN {
		t := "VPN connected"
		if !s.VPN {
			t = "VPN disconnected"
		}
		d.add(Event{Kind: "vpn", Start: s.At, Cause: CauseConfig, Title: t})
	}
}

// Finish closes events still open when monitoring stops.
func (d *Detector) Finish(at time.Time) {
	if d.outage != nil {
		d.outage.End = at
		d.outage.Cause = CauseUpstream
		if d.outTicks > 0 && float64(d.outRouter)/float64(d.outTicks) >= 0.5 {
			d.outage.Cause = CauseLocal
		}
		d.outage.Title = fmt.Sprintf("Internet unreachable for %s (still down when monitoring stopped)", human(d.outage.Duration()))
		d.Events = append(d.Events, *d.outage)
		d.outage = nil
	}
	d.closeLag(at)
	sort.SliceStable(d.Events, func(i, j int) bool { return d.Events[i].Start.Before(d.Events[j].Start) })
}

func human(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%.0f s", d.Seconds())
	case d < time.Hour:
		return fmt.Sprintf("%d min %d s", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%d h %d min", int(d.Hours()), int(d.Minutes())%60)
}

func nz(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
