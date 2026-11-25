// Package probe implements the network measurements in Go code instead of
// parsing ping/dig/traceroute output, which differs between OSes and locales.
package probe

import (
	"context"
	"encoding/json"
	"math"
	"sort"
	"sync"
	"time"
)

// Sample is one probe in a latency series.
type Sample struct {
	Seq   int     `json:"seq"`
	AtMs  float64 `json:"at_ms"` // send time, relative to the series start
	RTTMs float64 `json:"rtt_ms,omitempty"`
	Lost  bool    `json:"lost,omitempty"`
}

// PingResult is a latency series to one target, by ICMP echo or TCP connect.
type PingResult struct {
	Target      string    `json:"target"`
	Method      string    `json:"method"` // "icmp" or "tcp"
	Sent        int       `json:"sent"`
	Received    int       `json:"received"`
	RTTsMs      []float64 `json:"-"` // received RTTs in send order; derived from Samples
	Samples     []Sample  `json:"samples,omitempty"`
	Unavailable bool      `json:"unavailable,omitempty"` // OS doesn't permit unprivileged ICMP
	Err         string    `json:"error,omitempty"`
}

// finalize derives Sent, Received and RTTsMs from Samples.
func (p *PingResult) finalize() {
	p.Sent, p.Received, p.RTTsMs = len(p.Samples), 0, nil
	for _, s := range p.Samples {
		if !s.Lost {
			p.Received++
			p.RTTsMs = append(p.RTTsMs, s.RTTMs)
		}
	}
	if p.Received > 0 {
		p.Err = ""
	}
}

func (p *PingResult) UnmarshalJSON(b []byte) error {
	type alias PingResult
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*p = PingResult(a)
	if len(p.Samples) > 0 {
		p.finalize()
	}
	return nil
}

func (p PingResult) OK() bool { return p.Received > 0 }

func (p PingResult) LossPct() float64 {
	if p.Sent == 0 {
		return 0
	}
	return 100 * float64(p.Sent-p.Received) / float64(p.Sent)
}

func (p PingResult) AvgMs() float64 {
	if len(p.RTTsMs) == 0 {
		return 0
	}
	var s float64
	for _, r := range p.RTTsMs {
		s += r
	}
	return s / float64(len(p.RTTsMs))
}

func (p PingResult) MinMs() float64 {
	if len(p.RTTsMs) == 0 {
		return 0
	}
	m := math.Inf(1)
	for _, r := range p.RTTsMs {
		m = math.Min(m, r)
	}
	return m
}

func (p PingResult) MaxMs() float64 {
	var m float64
	for _, r := range p.RTTsMs {
		m = math.Max(m, r)
	}
	return m
}

// JitterMs is the mean absolute difference between consecutive RTTs.
func (p PingResult) JitterMs() float64 {
	if len(p.RTTsMs) < 2 {
		return 0
	}
	var s float64
	for i := 1; i < len(p.RTTsMs); i++ {
		s += math.Abs(p.RTTsMs[i] - p.RTTsMs[i-1])
	}
	return s / float64(len(p.RTTsMs)-1)
}

func (p PingResult) MarshalJSON() ([]byte, error) {
	type alias PingResult
	return json.Marshal(struct {
		alias
		LossPct  float64 `json:"loss_pct"`
		MedianMs float64 `json:"median_ms"`
		MinMs    float64 `json:"min_ms"`
		MaxMs    float64 `json:"max_ms"`
		JitterMs float64 `json:"jitter_ms"`
	}{alias(p), round1(p.LossPct()), round1(Median(p.RTTsMs)), round1(p.MinMs()), round1(p.MaxMs()), round1(p.JitterMs())})
}

// TCPPing measures latency by timing TCP handshakes (about one round trip),
// for networks or hosts where ICMP is blocked. Connects start on a fixed
// schedule and run concurrently, so a timeout doesn't delay the series.
// A refused connection still yields a valid round-trip time.
func TCPPing(ctx context.Context, target string, count int, interval, timeout time.Duration) PingResult {
	return TCPPingUntil(ctx, nil, target, count, interval, timeout)
}

// TCPPingUntil is TCPPing that stops starting new connects when stop closes.
func TCPPingUntil(ctx context.Context, stop <-chan struct{}, target string, count int, interval, timeout time.Duration) PingResult {
	res := PingResult{Target: target, Method: "tcp"}
	samples := make([]Sample, count)
	var wg sync.WaitGroup
	var errMu sync.Mutex
	start := time.Now()
	n := 0
	for i := range count {
		if !sleepStop(ctx, stop, time.Until(start.Add(time.Duration(i)*interval))) {
			break
		}
		n++
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := Sample{Seq: i + 1, AtMs: ms(time.Since(start))}
			r := TCPConnect(ctx, target, timeout)
			if r.HostAlive() {
				s.RTTMs = r.RTTMs
			} else {
				s.Lost = true
				errMu.Lock()
				res.Err = r.Err
				errMu.Unlock()
			}
			samples[i] = s
		}()
	}
	wg.Wait()
	res.Samples = samples[:n]
	res.finalize()
	return res
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }

// Median returns the median of xs, or 0 for an empty slice.
func Median(xs []float64) float64 { return Percentile(xs, 50) }

// Percentile returns the p-th percentile (0–100) of xs using linear
// interpolation between closest ranks; 0 for an empty slice.
func Percentile(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	if len(s) == 1 {
		return s[0]
	}
	pos := p / 100 * float64(len(s)-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	return s[lo] + (s[hi]-s[lo])*(pos-float64(lo))
}

// Window returns the samples sent between fromMs and toMs (relative to the
// series start), with counts and RTTs recomputed.
func Window(p PingResult, fromMs, toMs float64) PingResult {
	w := p
	w.Samples = nil
	for _, s := range p.Samples {
		if s.AtMs >= fromMs && s.AtMs <= toMs {
			w.Samples = append(w.Samples, s)
		}
	}
	w.finalize()
	return w
}
