//go:build !darwin && !linux && !windows

package probe

import (
	"context"
	"runtime"
	"time"
)

// Windows needs IcmpSendEcho via iphlpapi; not written yet. TCP probes
// cover reachability and latency in the meantime.
func Ping(ctx context.Context, target string, count int, interval, timeout time.Duration) PingResult {
	return PingUntil(ctx, nil, target, count, interval, timeout)
}

func PingUntil(ctx context.Context, stop <-chan struct{}, target string, count int, interval, timeout time.Duration) PingResult {
	return PingResult{Target: target, Method: "icmp", Unavailable: true, Err: "ICMP not implemented on " + runtime.GOOS + " yet"}
}
