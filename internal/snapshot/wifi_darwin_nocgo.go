//go:build darwin && !cgo

package snapshot

import (
	"context"
	"errors"
)

// Without cgo we can't call CoreWLAN. system_profiler works but takes ~20s,
// too slow for a 60-second triage, so Wi-Fi stats are reported as missing.
func platformWiFi(ctx context.Context, ifaces []Interface) (*WiFi, error) {
	for _, it := range ifaces {
		if it.Kind == KindWiFi {
			return &WiFi{Interface: it.Name, PowerOn: it.Up, Associated: it.Usable(), Source: "interface flags"},
				errors.New("signal stats unavailable: built without cgo")
		}
	}
	return nil, nil
}
