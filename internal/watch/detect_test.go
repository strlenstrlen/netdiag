package watch

import (
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

func ms(v float64) *float64 { return &v }

// feed runs a timeline: one entry per second, "." normal, "x" internet down
// with router up, "X" both down, "s" internet slow (400 ms) with router
// fast, "S" both slow.
func feed(d *Detector, timeline string, from int) {
	for i, c := range timeline {
		t := Tick{At: t0.Add(time.Duration(from+i) * time.Second), Router: ms(4), Inet: ms(15)}
		switch c {
		case 'x':
			t.Inet = nil
		case 'X':
			t.Inet, t.Router = nil, nil
		case 's':
			t.Inet = ms(400)
		case 'S':
			t.Inet, t.Router = ms(400), ms(380)
		}
		d.Tick(t)
	}
}

func only(t *testing.T, d *Detector, kind string) Event {
	t.Helper()
	var got []Event
	for _, e := range d.Events {
		if e.Kind == kind {
			got = append(got, e)
		}
	}
	if len(got) != 1 {
		t.Fatalf("want one %s event, got %d: %+v", kind, len(got), d.Events)
	}
	return got[0]
}

func TestOutageUpstream(t *testing.T) {
	d := &Detector{}
	feed(d, strings.Repeat(".", 20)+"xxxxx"+strings.Repeat(".", 5), 0)
	d.Finish(t0.Add(30 * time.Second))
	e := only(t, d, "outage")
	if e.Cause != CauseUpstream || e.Duration() != 5*time.Second || !e.Start.Equal(t0.Add(20*time.Second)) {
		t.Errorf("got %+v (duration %v)", e, e.Duration())
	}
}

func TestOutageLocal(t *testing.T) {
	d := &Detector{}
	feed(d, strings.Repeat(".", 20)+"XXXXXXXX"+strings.Repeat(".", 3), 0)
	if e := only(t, d, "outage"); e.Cause != CauseLocal {
		t.Errorf("cause = %s", e.Cause)
	}
}

func TestOutageDuringWiFiChange(t *testing.T) {
	d := &Detector{}
	d.State(State{At: t0, WiFiKnown: true, WiFiOn: true, Channel: 36, RSSI: -50})
	feed(d, strings.Repeat(".", 20)+"XXX", 0)
	d.State(State{At: t0.Add(23 * time.Second), WiFiKnown: true, WiFiOn: false})
	feed(d, "XX....", 23)
	e := only(t, d, "outage")
	if e.Cause != CauseWiFi {
		t.Errorf("cause = %s", e.Cause)
	}
	only(t, d, "wifi")
}

func TestSingleMissIsNotAnOutage(t *testing.T) {
	d := &Detector{}
	feed(d, strings.Repeat(".", 20)+"x"+strings.Repeat(".", 10)+"x....", 0)
	d.Finish(t0.Add(40 * time.Second))
	if len(d.Events) != 0 {
		t.Errorf("isolated misses produced events: %+v", d.Events)
	}
}

func TestLagUpstreamAndLocal(t *testing.T) {
	d := &Detector{}
	feed(d, strings.Repeat(".", 20)+"ssss"+strings.Repeat(".", 10)+"SSSS"+"...", 0)
	var causes []string
	for _, e := range d.Events {
		if e.Kind == "lag" {
			causes = append(causes, e.Cause)
		}
	}
	if strings.Join(causes, ",") != CauseUpstream+","+CauseLocal {
		t.Errorf("lag causes = %v; events %+v", causes, d.Events)
	}
}

func TestSpikesAreNotLag(t *testing.T) {
	// The AWDL pattern seen live: one slow sample every ~4 s.
	d := &Detector{}
	feed(d, strings.Repeat("...s", 15), 0)
	d.Finish(t0.Add(60 * time.Second))
	if len(d.Events) != 0 {
		t.Errorf("isolated spikes produced events: %+v", d.Events)
	}
}

func TestDNSFailureOnlyWhileUp(t *testing.T) {
	d := &Detector{}
	feed(d, "....", 0)
	d.DNS(t0.Add(4*time.Second), false, "dns-timeout")
	feed(d, "xxx", 5)
	d.DNS(t0.Add(7*time.Second), false, "dns-timeout") // during an outage: expected, not an event
	only(t, d, "dns")
}

func TestConfigChanges(t *testing.T) {
	d := &Detector{}
	d.State(State{At: t0, IPv4: "192.168.1.20", Gateway: "192.168.1.1", WiFiKnown: true, WiFiOn: true, Channel: 36, RSSI: -50})
	d.State(State{At: t0.Add(5 * time.Second), IPv4: "192.168.1.21", Gateway: "192.168.1.1", WiFiKnown: true, WiFiOn: true, Channel: 149, RSSI: -78, VPN: true})
	kinds := map[string]bool{}
	for _, e := range d.Events {
		kinds[e.Kind] = true
	}
	for _, k := range []string{"ip", "wifi", "vpn"} {
		if !kinds[k] {
			t.Errorf("missing %s event; got %+v", k, d.Events)
		}
	}
}

func TestConclusion(t *testing.T) {
	r := Results{IntervalMs: 1000}
	for i := 0; i < 60; i++ {
		r.Ticks = append(r.Ticks, Tick{At: t0.Add(time.Duration(i) * time.Second), Router: ms(4), Inet: ms(15)})
	}
	r.Router = "192.168.1.1"
	r.Events = []Event{{Kind: "outage", Start: t0.Add(10 * time.Second), End: t0.Add(20 * time.Second), Cause: CauseUpstream}}
	r.Summary = summarize(r, r.Events)
	c := Conclude(r)
	if c.Status != "fail" || !strings.Contains(c.Headline, "beyond your router") || r.Summary.UptimePct > 84 {
		t.Errorf("conclusion %+v uptime %v", c, r.Summary.UptimePct)
	}
	r.Events = append(r.Events, Event{Kind: "outage", Start: t0.Add(30 * time.Second), End: t0.Add(35 * time.Second), Cause: CauseWiFi})
	r.Summary = summarize(r, r.Events)
	if c := Conclude(r); !strings.Contains(c.Headline, "1 on your Wi-Fi or local network, 1 beyond your router") || !strings.HasPrefix(c.Owner, "Internet provider") {
		t.Errorf("mixed causes: %q owner %q", c.Headline, c.Owner)
	}
	r.Events = nil
	r.Summary = summarize(r, nil)
	if c := Conclude(r); c.Status != "ok" {
		t.Errorf("clean run: %+v", c)
	}
}
