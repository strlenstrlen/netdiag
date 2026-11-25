//go:build linux

package snapshot

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const cmdTimeout = 3 * time.Second

func platformInterfaceKinds(ctx context.Context) map[string]string {
	m := map[string]string{}
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return m
	}
	for _, e := range entries {
		name := e.Name()
		base := filepath.Join("/sys/class/net", name)
		if _, err := os.Stat(filepath.Join(base, "wireless")); err == nil {
			m[name] = KindWiFi
			continue
		}
		if _, err := os.Stat(filepath.Join(base, "bridge")); err == nil {
			m[name] = KindBridge
			continue
		}
		if t, err := os.ReadFile(filepath.Join(base, "type")); err == nil {
			// ARPHRD_NONE (65534) and ARPHRD_PPP (512) are tunnels.
			switch strings.TrimSpace(string(t)) {
			case "65534", "512":
				m[name] = KindVPN
				continue
			}
		}
		if _, err := os.Stat(filepath.Join(base, "device")); err == nil {
			m[name] = KindEthernet
		}
	}
	return m
}

func platformRoutes(ctx context.Context) (*Route, *Route, error) {
	b4, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil, nil, err
	}
	b6, _ := os.ReadFile("/proc/net/ipv6_route")
	return parseProcRoute(string(b4)), parseProcIPv6Route(string(b6)), nil
}

func platformDNS(ctx context.Context) ([]string, string, error) {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, "/etc/resolv.conf", err
	}
	servers := parseResolvConf(string(b))
	// systemd-resolved puts a local stub in resolv.conf; ask it for the
	// real upstream servers.
	if len(servers) == 1 && strings.HasPrefix(servers[0], "127.0.0.5") {
		if _, err := exec.LookPath("resolvectl"); err == nil {
			if out, err := runCmd(ctx, cmdTimeout, "resolvectl", "dns"); err == nil {
				if up := parseResolvectlDNS(out); len(up) > 0 {
					return up, "resolvectl dns", nil
				}
			}
		}
	}
	if len(servers) == 0 {
		return nil, "/etc/resolv.conf", errors.New("no nameservers configured")
	}
	return servers, "/etc/resolv.conf", nil
}

// Desktop proxy settings (GNOME/KDE) aren't read yet; env vars are
// collected by the cross-platform code.
func platformProxy(ctx context.Context) (Proxy, error) { return Proxy{}, nil }

var (
	iwBitrate = regexp.MustCompile(`tx bitrate:\s*([\d.]+)\s*MBit/s`)
	iwFreq    = regexp.MustCompile(`freq:\s*([\d.]+)`)
)

func platformWiFi(ctx context.Context, ifaces []Interface) (*WiFi, error) {
	var name string
	var up bool
	for _, it := range ifaces {
		if it.Kind == KindWiFi {
			name, up = it.Name, it.Up
			if it.Usable() {
				break
			}
		}
	}
	if name == "" {
		return nil, nil
	}
	w := &WiFi{Interface: name, PowerOn: up, Source: "/proc/net/wireless"}
	if b, err := os.ReadFile("/proc/net/wireless"); err == nil {
		if rssi, noise, ok := parseProcWireless(string(b), name); ok {
			w.Associated, w.SignalKnown, w.RSSI, w.Noise = true, true, rssi, noise
		}
	}
	if _, err := exec.LookPath("iw"); err == nil {
		if out, err := runCmd(ctx, cmdTimeout, "iw", "dev", name, "link"); err == nil {
			if strings.Contains(out, "Not connected") {
				w.Associated = false
			}
			if m := iwBitrate.FindStringSubmatch(out); m != nil {
				w.TxRateMbps, _ = strconv.ParseFloat(m[1], 64)
			}
			if m := iwFreq.FindStringSubmatch(out); m != nil {
				f, _ := strconv.ParseFloat(m[1], 64)
				switch {
				case f >= 5925:
					w.Band = "6 GHz"
				case f >= 4900:
					w.Band = "5 GHz"
				case f > 0:
					w.Band = "2.4 GHz"
				}
			}
			w.Source += " + iw"
		}
	}
	return w, nil
}
