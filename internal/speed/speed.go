// Package speed is stage 3: download/upload throughput from two
// independent providers, and how much latency rises while the link is busy
// (bufferbloat), the most common reason calls stutter while someone else
// is downloading.
package speed

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/strlenstrlen/netdiag/internal/config"
	"github.com/strlenstrlen/netdiag/internal/probe"
	"github.com/strlenstrlen/netdiag/internal/quality"
)

const (
	ProviderCloudflare = "Cloudflare"
	ProviderMLab       = "M-Lab NDT7"
	Download           = "download"
	RateLimited        = "rate-limited"
	Upload             = "upload"

	loadedInterval = 100 * time.Millisecond // transfers can end in ~3 s at the data cap
	rampUp         = time.Second            // loaded-latency samples from the first second are ignored
)

// Plan says where to measure latency under load and what it was when idle.
type Plan struct {
	Router          *quality.Target `json:"router,omitempty"`
	Internet        *quality.Target `json:"internet,omitempty"`
	IdleRouterP50   float64         `json:"idle_router_p50_ms"`
	IdleInternetP50 float64         `json:"idle_internet_p50_ms"`
	PlanDownMbps    float64         `json:"plan_down_mbps,omitempty"` // what the user pays for, if given
	PlanUpMbps      float64         `json:"plan_up_mbps,omitempty"`
}

// PlanFrom takes targets and idle baselines from stage 2.
func PlanFrom(q *quality.Results) Plan {
	var p Plan
	if q == nil {
		return p
	}
	p.Router = q.Plan.Router
	if len(q.Plan.Internet) > 0 {
		t := q.Plan.Internet[0]
		p.Internet = &t
	}
	if q.Router != nil {
		p.IdleRouterP50 = q.Router.Stats.P50Ms
	}
	if len(q.Internet) > 0 {
		p.IdleInternetP50 = q.Internet[0].Stats.P50Ms
	}
	return p
}

// Loaded is latency measured while a transfer was running.
type Loaded struct {
	Router   *quality.Stats     `json:"router,omitempty"`
	Internet *quality.Stats     `json:"internet,omitempty"`
	Raw      []probe.PingResult `json:"raw,omitempty"` // full series; Window* bound the loaded part
	WindowMs [2]float64         `json:"window_ms"`
}

type Transfer struct {
	Provider   string  `json:"provider"`
	Server     string  `json:"server,omitempty"`
	Direction  string  `json:"direction"`
	OK         bool    `json:"ok"`
	Mbps       float64 `json:"mbps"`
	ClientMbps float64 `json:"client_mbps,omitempty"` // NDT7 upload: our own count, for comparison
	Bytes      int64   `json:"bytes"`
	DurationMs float64 `json:"duration_ms"`
	Streams    int     `json:"streams"`
	Capped     bool    `json:"capped,omitempty"` // stopped early at the data cap
	Err        string  `json:"error,omitempty"`
	Loaded     Loaded  `json:"loaded"`
}

type Results struct {
	Plan       Plan       `json:"plan"`
	Transfers  []Transfer `json:"transfers"`
	DataMB     float64    `json:"data_mb"`
	DurationMs float64    `json:"duration_ms"`
}

// Best returns the fastest successful transfer in a direction. The best
// result reflects what the line can do; a slower provider usually means a
// congested route to that provider.
func (r Results) Best(dir string) *Transfer {
	var best *Transfer
	for i, t := range r.Transfers {
		if t.Direction == dir && t.OK && (best == nil || t.Mbps > best.Mbps) {
			best = &r.Transfers[i]
		}
	}
	return best
}

// WorstLoaded returns, for a direction, the largest rise in median latency
// under load over idle, for the internet and router series.
func (r Results) WorstLoaded(dir string) (inetRise, routerRise float64, loss float64, ok bool) {
	for _, t := range r.Transfers {
		if t.Direction != dir || !t.OK || t.Loaded.Internet == nil || t.Loaded.Internet.Received < 3 {
			continue
		}
		ok = true
		inetRise = math.Max(inetRise, t.Loaded.Internet.P50Ms-r.Plan.IdleInternetP50)
		loss = math.Max(loss, t.Loaded.Internet.LossPct)
		if t.Loaded.Router != nil && t.Loaded.Router.Received >= 3 {
			routerRise = math.Max(routerRise, t.Loaded.Router.P50Ms-r.Plan.IdleRouterP50)
		}
	}
	return
}

type Options struct{ Progress func(string) }

func Run(ctx context.Context, cfg config.Config, plan Plan, opts Options) Results {
	progress := opts.Progress
	if progress == nil {
		progress = func(string) {}
	}
	start := time.Now()
	res := Results{Plan: plan}
	limit := time.Duration(cfg.SpeedSeconds) * time.Second
	capBytes := int64(cfg.SpeedMaxMB) << 20

	progress("Finding a nearby M-Lab server…")
	servers, locErr := ndt7Locate(ctx, cfg.NDT7LocateURL, 5*time.Second)

	type job struct {
		provider, dir string
		run           func(ctx context.Context, m *meter, stop context.CancelFunc) (server string, serverMbps float64, err error)
	}
	var jobs []job
	for _, dir := range []string{Download, Upload} {
		jobs = append(jobs, job{ProviderCloudflare, dir, func(ctx context.Context, m *meter, stop context.CancelFunc) (string, float64, error) {
			if dir == Download {
				return "speed.cloudflare.com", 0, cloudflareDownload(ctx, cfg.CloudflareDownURL, cfg.CloudflareStreams, m, capBytes, stop)
			}
			return "speed.cloudflare.com", 0, cloudflareUpload(ctx, cfg.CloudflareUpURL, cfg.CloudflareStreams, m, capBytes, stop)
		}})
		jobs = append(jobs, job{ProviderMLab, dir, func(ctx context.Context, m *meter, stop context.CancelFunc) (string, float64, error) {
			if locErr != nil {
				return "", 0, locErr
			}
			// The locate tokens are short-lived and single-use, so try the
			// next server only if connecting fails.
			var err error
			for _, s := range servers {
				if dir == Download {
					err = ndt7Download(ctx, s.Download, m, capBytes, stop)
					if err == nil || m.total() > 0 {
						return s.label(), 0, err
					}
				} else {
					var sm float64
					sm, err = ndt7Upload(ctx, s.Upload, m, capBytes, stop)
					if err == nil || m.total() > 0 {
						return s.label(), sm, err
					}
				}
			}
			return "", 0, err
		}})
	}

	for _, j := range jobs {
		streams := 1
		if j.provider == ProviderCloudflare {
			streams = cfg.CloudflareStreams
		}
		t := Transfer{Provider: j.provider, Direction: j.dir, Streams: streams}

		// Latency samplers start first and keep sending until the transfer ends.
		stopPing := make(chan struct{})
		pingStart := time.Now()
		var wg sync.WaitGroup
		var routerP, inetP probe.PingResult
		maxSamples := int((limit+2*time.Second)/loadedInterval) + 1
		sampler := func(tg *quality.Target, out *probe.PingResult) {
			if tg == nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				if tg.Method == "tcp" {
					*out = probe.TCPPingUntil(ctx, stopPing, tg.Addr, maxSamples, loadedInterval, 2*time.Second)
				} else {
					*out = probe.PingUntil(ctx, stopPing, tg.Addr, maxSamples, loadedInterval, 2*time.Second)
				}
			}()
		}
		sampler(plan.Router, &routerP)
		sampler(plan.Internet, &inetP)

		tctx, cancel := context.WithTimeout(ctx, limit)
		m := newMeter()
		meterDone := make(chan struct{})
		go func() { m.run(tctx, 100*time.Millisecond); close(meterDone) }()
		go countdown(tctx, progress, fmt.Sprintf("Measuring %s speed (%s)…", j.dir, j.provider), limit)

		xferStart := time.Since(pingStart)
		server, serverMbps, err := j.run(tctx, m, cancel)
		capped := m.total() >= capBytes
		cancel()
		<-meterDone
		xferEnd := time.Since(pingStart)
		close(stopPing)
		wg.Wait()

		mbps, bytes, dur := m.rate()
		t.Server, t.Bytes, t.DurationMs, t.Capped = server, bytes, float64(dur.Milliseconds()), capped
		t.Mbps = round1(mbps)
		if serverMbps > 0 { // NDT7 upload: trust the receiver's count
			t.ClientMbps, t.Mbps = t.Mbps, round1(serverMbps)
		}
		t.OK = bytes > 0 && dur >= time.Second && t.Mbps > 0
		if err != nil && !t.OK {
			t.Err = err.Error()
			if strings.Contains(t.Err, "HTTP 429") {
				t.Err = RateLimited + " (too many speed tests from this connection recently; try again later)"
			}
		}

		from := float64((xferStart + rampUp).Milliseconds())
		to := float64(xferEnd.Milliseconds())
		t.Loaded.WindowMs = [2]float64{from, to}
		if plan.Router != nil {
			s := quality.Summarize(probe.Window(routerP, from, to))
			t.Loaded.Router = &s
			t.Loaded.Raw = append(t.Loaded.Raw, routerP)
		}
		if plan.Internet != nil {
			s := quality.Summarize(probe.Window(inetP, from, to))
			t.Loaded.Internet = &s
			t.Loaded.Raw = append(t.Loaded.Raw, inetP)
		}

		res.DataMB += float64(bytes) / 1e6
		res.Transfers = append(res.Transfers, t)
		if ctx.Err() != nil {
			break
		}
	}
	res.DataMB = round1(res.DataMB)
	res.DurationMs = float64(time.Since(start).Milliseconds())
	return res
}

func countdown(ctx context.Context, progress func(string), label string, d time.Duration) {
	end := time.Now().Add(d)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		progress(fmt.Sprintf("%s %ds left", label, max(0, int(time.Until(end).Round(time.Second).Seconds()))))
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }
