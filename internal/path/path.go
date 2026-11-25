// Package path traces the route to a host hop by hop, several rounds per
// hop (like mtr), and concludes where loss or delay begins.
package path

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/strlenstrlen/netdiag/internal/probe"
	"github.com/strlenstrlen/netdiag/internal/target"
)

type Hop struct {
	TTL      int       `json:"ttl"`
	Addr     string    `json:"addr,omitempty"` // most frequent responder ("" if none answered)
	Others   []string  `json:"other_addrs,omitempty"`
	Name     string    `json:"name,omitempty"` // reverse DNS
	Sent     int       `json:"sent"`
	Received int       `json:"received"`
	RTTsMs   []float64 `json:"rtts_ms,omitempty"`
	Final    bool      `json:"final,omitempty"` // the destination itself
}

func (h Hop) LossPct() float64 {
	if h.Sent == 0 {
		return 0
	}
	return 100 * float64(h.Sent-h.Received) / float64(h.Sent)
}

func (h Hop) P50() float64 { return probe.Median(h.RTTsMs) }

type Trace struct {
	Target     string            `json:"target"`
	Addr       string            `json:"addr"`
	Rounds     int               `json:"rounds"`
	Hops       []Hop             `json:"hops"`
	Reached    bool              `json:"reached"`
	Err        string            `json:"error,omitempty"`
	Conclusion target.Conclusion `json:"conclusion"`
}

type Options struct {
	Rounds   int
	MaxHops  int
	Progress func(string)
}

// reply is one answer to one probe.
type reply struct {
	ttl   int
	from  string
	rtt   float64
	final bool
}

// Run resolves host, traces it, names the hops and draws a conclusion.
func Run(ctx context.Context, host string, o Options) Trace {
	t := Trace{Target: host, Rounds: o.Rounds}
	ip := net.ParseIP(host)
	if ip == nil {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err := net.DefaultResolver.LookupIPAddr(c, host)
		cancel()
		if err != nil || len(addrs) == 0 {
			t.Err = "couldn't resolve " + host
			t.Conclusion = target.Conclusion{Status: "fail", Headline: "Couldn't find an address for " + host,
				NextSteps: []string{"Run `netdiag dns " + host + "` to see why"}}
			return t
		}
		for _, a := range addrs {
			if a.IP.To4() != nil { // IPv4 first: the trace is IPv4-only for now
				ip = a.IP
				break
			}
		}
		if ip == nil {
			t.Err = "only IPv6 addresses found; IPv6 tracing isn't supported yet"
			t.Conclusion = target.Conclusion{Status: "fail", Headline: t.Err}
			return t
		}
	}
	t.Addr = ip.String()
	if ip.To4() == nil {
		t.Err = "IPv6 tracing isn't supported yet"
		t.Conclusion = target.Conclusion{Status: "fail", Headline: t.Err}
		return t
	}

	replies, sent, err := trace(ctx, ip.To4(), o)
	if err != nil {
		t.Err = err.Error()
		t.Conclusion = target.Conclusion{Status: "fail", Headline: "Couldn't trace the path: " + err.Error()}
		return t
	}
	t.Hops, t.Reached = assemble(replies, sent)
	nameHops(ctx, t.Hops)
	t.Conclusion = Conclude(t)
	return t
}

// assemble groups replies by TTL, stopping at the first TTL that reached
// the destination. sent[ttl] is how many probes went out at that TTL.
func assemble(replies []reply, sent map[int]int) ([]Hop, bool) {
	final := 0
	for _, r := range replies {
		if r.final && (final == 0 || r.ttl < final) {
			final = r.ttl
		}
	}
	last := final
	if last == 0 {
		for ttl := range sent {
			last = max(last, ttl)
		}
		// Trim trailing silent hops beyond the last one that answered.
		answered := 0
		for _, r := range replies {
			answered = max(answered, r.ttl)
		}
		last = min(last, answered+1)
	}
	byTTL := map[int][]reply{}
	for _, r := range replies {
		if r.ttl <= last {
			byTTL[r.ttl] = append(byTTL[r.ttl], r)
		}
	}
	var hops []Hop
	for ttl := 1; ttl <= last; ttl++ {
		h := Hop{TTL: ttl, Sent: sent[ttl], Final: ttl == final}
		counts := map[string]int{}
		for _, r := range byTTL[ttl] {
			h.Received++
			h.RTTsMs = append(h.RTTsMs, r.rtt)
			counts[r.from]++
		}
		var addrs []string
		for a := range counts {
			addrs = append(addrs, a)
		}
		sort.Slice(addrs, func(i, j int) bool { return counts[addrs[i]] > counts[addrs[j]] })
		if len(addrs) > 0 {
			h.Addr, h.Others = addrs[0], addrs[1:]
		}
		h.Received = min(h.Received, h.Sent)
		hops = append(hops, h)
	}
	return hops, final > 0
}

func nameHops(ctx context.Context, hops []Hop) {
	var wg sync.WaitGroup
	for i := range hops {
		if hops[i].Addr == "" {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			defer cancel()
			if names, err := net.DefaultResolver.LookupAddr(c, hops[i].Addr); err == nil && len(names) > 0 {
				hops[i].Name = strings.TrimSuffix(names[0], ".")
			}
		}()
	}
	wg.Wait()
}

// Where describes who probably runs a hop, from its position and address.
func Where(h Hop, index int) string {
	ip := net.ParseIP(h.Addr)
	switch {
	case h.Final:
		return "destination"
	case index == 0 && ip != nil && ip.IsPrivate():
		return "your router"
	case ip != nil && (ip.IsPrivate() || inCGNAT(ip)):
		return "provider's local network"
	case index <= 3:
		return "likely your provider"
	}
	return "internet"
}

func inCGNAT(ip net.IP) bool {
	_, n, _ := net.ParseCIDR("100.64.0.0/10")
	return n.Contains(ip)
}

// Conclude reads the trace the way an experienced engineer reads mtr:
// loss or delay only counts if it persists all the way to the destination;
// a single hop that drops or slowly answers probes is just deprioritizing
// them.
func Conclude(t Trace) target.Conclusion {
	if len(t.Hops) == 0 {
		return target.Conclusion{Status: "fail", Headline: "No hop answered", Owner: "The network you're on",
			NextSteps: []string{"Run netdiag without arguments to check your connection"}}
	}
	label := func(i int) string {
		h := t.Hops[i]
		s := fmt.Sprintf("hop %d", h.TTL)
		if h.Addr != "" {
			s += " (" + nz(h.Name, h.Addr) + ", " + Where(h, i) + ")"
		}
		return s
	}
	var c target.Conclusion
	last := len(t.Hops) - 1
	dest := t.Hops[last]

	if !t.Reached {
		lastAns := -1
		for i, h := range t.Hops {
			if h.Received > 0 {
				lastAns = i
			}
		}
		c = target.Conclusion{Status: "warn", Owner: "Unknown",
			Headline: fmt.Sprintf("%s didn't answer the trace", t.Target),
			Evidence: []string{"Many servers and firewalls ignore these probes, so this alone doesn't mean it's down"},
			NextSteps: []string{
				fmt.Sprintf("Run `netdiag site %s` to test the service itself", t.Target),
			}}
		if lastAns >= 0 {
			c.Evidence = append([]string{"The path was traced as far as " + label(lastAns)}, c.Evidence...)
		}
		return c
	}

	// Loss that persists to the destination.
	destLoss := dest.LossPct()
	destLost := dest.Sent - dest.Received
	origin := -1
	// One lost probe is noise (or the destination rate-limiting replies);
	// it takes at least two to call it loss.
	if destLoss >= 5 && destLost >= 2 {
		for i := 0; i <= last; i++ {
			persists := true
			for j := i; j <= last; j++ {
				if t.Hops[j].Received > 0 && t.Hops[j].LossPct() < destLoss/2 {
					persists = false
					break
				}
			}
			if persists && t.Hops[i].LossPct() >= destLoss/2 {
				origin = i
				break
			}
		}
	}

	// The largest delay increase that the destination still shows.
	jumpAt, jump := -1, 0.0
	prev, prevI := 0.0, -1
	for i, h := range t.Hops {
		if h.Received == 0 {
			continue
		}
		p := h.P50()
		if prevI >= 0 && p-prev > jump && dest.P50() >= p-(p-prev)*0.3 {
			jumpAt, jump = i, p-prev
		}
		prev, prevI = p, i
	}

	ev := []string{fmt.Sprintf("Reached %s in %d hops; %.0f ms round trip, %.0f%% loss", nz(t.Addr, t.Target), dest.TTL, dest.P50(), destLoss)}
	destOnly := origin == last
	switch {
	case destOnly:
		c = target.Conclusion{Status: "ok", Headline: fmt.Sprintf("The path to %s is healthy", t.Target),
			Evidence: append(ev, fmt.Sprintf("Only the destination itself missed probes (%d of %d); hops before it lost none, so it is rate-limiting replies, not losing traffic", destLost, dest.Sent))}
	case origin >= 0:
		owner := "Your internet provider"
		switch Where(t.Hops[origin], origin) {
		case "your router":
			owner = "Wi-Fi / local network"
		case "internet", "destination":
			owner = "A network between your provider and the destination"
		}
		c = target.Conclusion{Status: "warn", Owner: owner,
			Headline: fmt.Sprintf("Packet loss starts at %s", label(origin)),
			Evidence: append(ev, "Every hop from there to the destination loses packets, so the loss is real, not just a router ignoring probes"),
			NextSteps: []string{
				"If it's your router or provider, restart the modem and router",
				"If it persists, send this trace to your internet provider",
			}}
	case jumpAt >= 0 && jump >= 50 && dest.P50() >= 100:
		c = target.Conclusion{Status: "warn", Owner: "Whoever runs " + label(jumpAt),
			Headline: fmt.Sprintf("Most of the delay is added at %s (+%.0f ms)", label(jumpAt), jump),
			Evidence: append(ev, "Long distances (other continents, satellite links) add delay like this naturally"),
		}
	default:
		c = target.Conclusion{Status: "ok", Headline: fmt.Sprintf("The path to %s is healthy", t.Target), Evidence: ev}
	}
	for i, h := range t.Hops[:last] {
		if h.Received > 0 && h.LossPct() >= 20 && h.Sent-h.Received >= 2 && (origin < 0 || i < origin) {
			c.Evidence = append(c.Evidence, fmt.Sprintf("%s drops %.0f%% of probes but later hops don't, so it just ignores some probes; not a problem", label(i), h.LossPct()))
			break
		}
	}
	return c
}

func nz(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
