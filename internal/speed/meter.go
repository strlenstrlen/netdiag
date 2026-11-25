package speed

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// meter counts transferred bytes and samples the running total so the
// result can exclude TCP ramp-up at the start of a transfer.
type meter struct {
	n     atomic.Int64
	start time.Time

	mu      sync.Mutex
	samples []point
}

type point struct {
	t time.Duration
	b int64
}

func newMeter() *meter { return &meter{start: time.Now()} }

func (m *meter) add(n int64) { m.n.Add(n) }

func (m *meter) total() int64 { return m.n.Load() }

// run samples every interval until ctx is done, then takes a final sample.
func (m *meter) run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			m.sample()
			return
		case <-t.C:
			m.sample()
		}
	}
}

func (m *meter) sample() {
	m.mu.Lock()
	m.samples = append(m.samples, point{time.Since(m.start), m.n.Load()})
	m.mu.Unlock()
}

// rate returns steady-state Mbps: the average after the first quarter of the
// transfer (at most 1.5 s), which skips TCP slow start and the burst of bytes
// that only filled socket buffers. Falls back to the overall average.
func (m *meter) rate() (mbps float64, bytes int64, dur time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.samples) == 0 {
		return 0, m.n.Load(), time.Since(m.start)
	}
	end := m.samples[len(m.samples)-1]
	bytes, dur = end.b, end.t
	warm := min(dur/4, 1500*time.Millisecond)
	from := point{}
	for _, s := range m.samples {
		if s.t >= warm {
			from = s
			break
		}
	}
	span := end.t - from.t
	if span < 500*time.Millisecond {
		from, span = point{}, end.t
	}
	if span <= 0 {
		return 0, bytes, dur
	}
	return float64(end.b-from.b) * 8 / span.Seconds() / 1e6, bytes, dur
}
