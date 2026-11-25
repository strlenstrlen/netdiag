package quality

import (
	"math/rand"
	"testing"

	"github.com/strlenstrlen/netdiag/internal/probe"
)

func build(spikeAt func(seq int) bool) probe.PingResult {
	var p probe.PingResult
	for seq := 1; seq <= 100; seq++ {
		s := probe.Sample{Seq: seq, AtMs: float64(seq-1) * 200, RTTMs: 5}
		if spikeAt(seq) {
			s.RTTMs = 150
		}
		p.Samples = append(p.Samples, s)
		p.RTTsMs = append(p.RTTsMs, s.RTTMs)
	}
	p.Sent, p.Received = 100, 100
	return p
}

func TestSpikePeriodDetectsTimer(t *testing.T) {
	// Spike pattern seen live on a Mac: gaps alternate 3 and 5 samples,
	// with one multi-sample stall in the middle.
	gaps := []int{5, 3, 5, 5, 3}
	at := map[int]bool{}
	for seq, i := 4, 0; seq <= 100; i++ {
		at[seq] = true
		seq += gaps[i%len(gaps)]
	}
	for s := 25; s <= 29; s++ {
		at[s] = true
	}
	st := Summarize(build(func(s int) bool { return at[s] }))
	if st.SpikePeriodMs < 700 || st.SpikePeriodMs > 1000 {
		t.Errorf("period = %v ms, want about 840", st.SpikePeriodMs)
	}
}

func TestSpikePeriodIgnoresRandomSpikes(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	at := map[int]bool{}
	for len(at) < 12 {
		at[1+rng.Intn(100)] = true
	}
	if st := Summarize(build(func(s int) bool { return at[s] })); st.SpikePeriodMs != 0 {
		t.Errorf("random spikes reported as periodic every %v ms", st.SpikePeriodMs)
	}
}

func TestCorrelationSeparatesLocalFromUpstream(t *testing.T) {
	mk := func(spikes ...int) *Series {
		m := map[int]bool{}
		for _, s := range spikes {
			m[s] = true
		}
		p := build(func(s int) bool { return m[s] })
		return &Series{Probe: p, Stats: Summarize(p)}
	}
	router := mk(10, 30, 50, 70)
	shared := Correlate(router, []Series{*mk(10, 31, 50, 70)})
	if shared.SharedFraction() != 1 {
		t.Errorf("same-moment spikes: shared = %v", shared.SharedFraction())
	}
	apart := Correlate(router, []Series{*mk(15, 40, 60, 85)})
	if apart.SharedFraction() != 0 || apart.RouterOnlyEvents != 4 {
		t.Errorf("separate spikes: %+v", apart)
	}
}
