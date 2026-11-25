package path

import (
	"strings"
	"testing"
)

// hop builds a hop with `lost` of 15 probes lost, each reply at ms.
func hop(ttl int, addr string, ms float64, lost int, final bool) Hop {
	h := Hop{TTL: ttl, Addr: addr, Sent: 15, Received: 15 - lost, Final: final}
	for range h.Received {
		h.RTTsMs = append(h.RTTsMs, ms)
	}
	return h
}

func TestConclusions(t *testing.T) {
	tests := []struct {
		name     string
		hops     []Hop
		reached  bool
		status   string
		headline string
	}{
		{"healthy", []Hop{hop(1, "192.168.0.1", 4, 0, false), hop(2, "203.0.113.14", 8, 0, false), hop(3, "1.1.1.1", 10, 0, true)}, true, "ok", "healthy"},
		{"one lost probe at the destination is noise", []Hop{hop(1, "192.168.0.1", 4, 0, false), hop(2, "1.1.1.1", 10, 1, true)}, true, "ok", "healthy"},
		{"destination rate-limits replies", []Hop{hop(1, "192.168.0.1", 4, 0, false), hop(2, "203.0.113.14", 8, 0, false), hop(3, "1.1.1.1", 10, 4, true)}, true, "ok", "healthy"},
		{"loss starts at the provider", []Hop{hop(1, "192.168.0.1", 4, 0, false), hop(2, "203.0.113.14", 8, 4, false), hop(3, "198.51.100.77", 9, 4, false), hop(4, "1.1.1.1", 10, 5, true)}, true, "warn", "hop 2"},
		{"loss starts on the Wi-Fi", []Hop{hop(1, "192.168.0.1", 4, 5, false), hop(2, "203.0.113.14", 8, 5, false), hop(3, "1.1.1.1", 10, 5, true)}, true, "warn", "your router"},
		{"router ignoring probes isn't loss", []Hop{hop(1, "192.168.0.1", 4, 0, false), hop(2, "203.0.113.14", 8, 9, false), hop(3, "1.1.1.1", 10, 0, true)}, true, "ok", "healthy"},
		{"long-haul delay", []Hop{hop(1, "192.168.0.1", 4, 0, false), hop(2, "203.0.113.14", 10, 0, false), hop(3, "62.115.1.1", 150, 0, false), hop(4, "203.0.113.9", 155, 0, true)}, true, "warn", "+140 ms"},
		{"destination ignores probes", []Hop{hop(1, "192.168.0.1", 4, 0, false), {TTL: 2, Sent: 15}}, false, "warn", "didn't answer"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := Conclude(Trace{Target: "example", Hops: tc.hops, Reached: tc.reached})
			if c.Status != tc.status || !strings.Contains(c.Headline, tc.headline) {
				t.Errorf("got %s %q; evidence %v", c.Status, c.Headline, c.Evidence)
			}
		})
	}
}

func TestAssembleStopsAtDestination(t *testing.T) {
	replies := []reply{
		{ttl: 1, from: "192.168.0.1", rtt: 4}, {ttl: 2, from: "10.0.0.1", rtt: 8},
		{ttl: 3, from: "1.1.1.1", rtt: 10, final: true}, {ttl: 4, from: "1.1.1.1", rtt: 10, final: true},
	}
	hops, reached := assemble(replies, map[int]int{1: 1, 2: 1, 3: 1, 4: 1})
	if !reached || len(hops) != 3 || !hops[2].Final || Where(hops[1], 1) != "provider's local network" {
		t.Errorf("reached=%v hops=%+v", reached, hops)
	}
}
