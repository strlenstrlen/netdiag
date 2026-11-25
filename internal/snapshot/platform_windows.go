//go:build windows

package snapshot

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

// One PowerShell call (about a second to start) feeds routes, DNS, adapter
// kinds and proxy settings. Results are reused for 2 seconds so a single
// Collect doesn't start PowerShell four times.
var (
	winMu   sync.Mutex
	winAt   time.Time
	winData winNet
	winErr  error
)

func winNetInfo(ctx context.Context) (winNet, error) {
	winMu.Lock()
	defer winMu.Unlock()
	if time.Since(winAt) < 2*time.Second {
		return winData, winErr
	}
	out, err := runCmd(ctx, 10*time.Second, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", winPowerShell)
	if err != nil {
		winData, winErr = winNet{}, errors.New("PowerShell: "+err.Error())
	} else {
		winData, winErr = parseWinNet(out)
	}
	winAt = time.Now()
	return winData, winErr
}

func platformInterfaceKinds(ctx context.Context) map[string]string {
	w, err := winNetInfo(ctx)
	if err != nil {
		return map[string]string{}
	}
	return w.kinds()
}

func platformRoutes(ctx context.Context) (*Route, *Route, error) {
	w, err := winNetInfo(ctx)
	if err != nil {
		return nil, nil, err
	}
	r4, r6 := w.routes()
	return r4, r6, nil
}

func platformDNS(ctx context.Context) ([]string, string, error) {
	w, err := winNetInfo(ctx)
	if err != nil {
		return nil, "Get-DnsClientServerAddress", err
	}
	alias := ""
	if r4, _ := w.routes(); r4 != nil {
		alias = r4.Interface
	}
	s := w.dnsFor(alias)
	if len(s) == 0 {
		return nil, "Get-DnsClientServerAddress", errors.New("no DNS servers configured")
	}
	return s, "Get-DnsClientServerAddress", nil
}

func platformProxy(ctx context.Context) (Proxy, error) {
	w, err := winNetInfo(ctx)
	if err != nil {
		return Proxy{}, err
	}
	return w.proxy(), nil
}

func platformWiFi(ctx context.Context, ifaces []Interface) (*WiFi, error) {
	out, err := runCmd(ctx, 5*time.Second, "netsh", "wlan", "show", "interfaces")
	if err != nil || strings.Contains(strings.ToLower(out), "no wireless interface") {
		return nil, nil
	}
	if w, ok := parseNetshWLAN(out); ok {
		return &w, nil
	}
	// Non-English Windows: fall back to whether a Wi-Fi adapter is up.
	for _, it := range ifaces {
		if it.Kind == KindWiFi {
			return &WiFi{Interface: it.Name, PowerOn: it.Up, Associated: it.Usable(), Source: "interface flags"},
				errors.New("Wi-Fi signal details are only read on English Windows")
		}
	}
	return nil, nil
}
