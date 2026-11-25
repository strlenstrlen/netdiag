package probe

import (
	"encoding/json"
	"math"
	"testing"
)

func TestPingStats(t *testing.T) {
	p := PingResult{Sent: 5, Received: 4, RTTsMs: []float64{10, 20, 10, 40}}
	if p.LossPct() != 20 {
		t.Errorf("loss = %v", p.LossPct())
	}
	if p.AvgMs() != 20 || p.MinMs() != 10 || p.MaxMs() != 40 {
		t.Errorf("avg/min/max = %v/%v/%v", p.AvgMs(), p.MinMs(), p.MaxMs())
	}
	// |20-10| + |10-20| + |40-10| = 50, over 3 gaps
	if math.Abs(p.JitterMs()-50.0/3) > 1e-9 {
		t.Errorf("jitter = %v", p.JitterMs())
	}
	if Median([]float64{5, 1, 3}) != 3 || Median([]float64{4, 1, 3, 2}) != 2.5 || Median(nil) != 0 {
		t.Error("median")
	}
}

func TestPercentile(t *testing.T) {
	xs := []float64{10, 20, 30, 40, 50}
	if Percentile(xs, 50) != 30 || Percentile(xs, 0) != 10 || Percentile(xs, 100) != 50 || Percentile(xs, 95) != 48 {
		t.Errorf("p50=%v p95=%v", Percentile(xs, 50), Percentile(xs, 95))
	}
}

func TestPingJSONRoundTrip(t *testing.T) {
	p := PingResult{Target: "x", Method: "icmp", Samples: []Sample{{Seq: 1, RTTMs: 5}, {Seq: 2, Lost: true}, {Seq: 3, RTTMs: 7}}}
	p.finalize()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var back PingResult
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Sent != 3 || back.Received != 2 || len(back.RTTsMs) != 2 || back.RTTsMs[1] != 7 {
		t.Errorf("round trip lost data: %+v", back)
	}
}
