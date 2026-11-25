// Package snapshot collects the machine's network configuration without
// sending any traffic: interfaces, routes, DNS servers, proxy, Wi-Fi and VPN.
// Cross-platform logic lives here; OS-specific collection lives in the
// platform_*.go files.
package snapshot

import (
	"context"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	KindWiFi     = "wifi"
	KindEthernet = "ethernet"
	KindVPN      = "vpn"
	KindLoopback = "loopback"
	KindBridge   = "bridge"
	KindOther    = "other"
)

type Snapshot struct {
	OS               string      `json:"os"`
	Arch             string      `json:"arch"`
	Hostname         string      `json:"hostname"`
	CollectedAt      time.Time   `json:"collected_at"`
	Interfaces       []Interface `json:"interfaces"`
	PrimaryInterface string      `json:"primary_interface,omitempty"`
	DefaultRoute     *Route      `json:"default_route,omitempty"`
	DefaultRoute6    *Route      `json:"default_route_v6,omitempty"`
	DNSServers       []string    `json:"dns_servers"`
	DNSSource        string      `json:"dns_source,omitempty"`
	Proxy            Proxy       `json:"proxy"`
	WiFi             *WiFi       `json:"wifi,omitempty"`
	VPN              VPNInfo     `json:"vpn"`
	Errors           []string    `json:"collection_errors,omitempty"`
}

type Interface struct {
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	Up         bool     `json:"up"`
	Running    bool     `json:"running"`
	MAC        string   `json:"mac,omitempty"`
	MTU        int      `json:"mtu"`
	IPv4       []string `json:"ipv4,omitempty"`
	IPv6       []string `json:"ipv6,omitempty"` // global and unique-local only
	LinkLocal6 bool     `json:"link_local_v6,omitempty"`
}

// SelfAssignedOnly is true when the interface's only IPv4 addresses are
// 169.254.x.x, which is what the OS assigns when DHCP gets no answer.
func (i Interface) SelfAssignedOnly() bool {
	if len(i.IPv4) == 0 {
		return false
	}
	for _, a := range i.IPv4 {
		if !strings.HasPrefix(a, "169.254.") {
			return false
		}
	}
	return true
}

func (i Interface) RoutableIPv4() []string {
	var out []string
	for _, a := range i.IPv4 {
		if !strings.HasPrefix(a, "169.254.") {
			out = append(out, a)
		}
	}
	return out
}

// Usable means the interface could carry internet traffic.
func (i Interface) Usable() bool {
	if !i.Up || i.Kind == KindLoopback {
		return false
	}
	return len(i.RoutableIPv4()) > 0 || len(i.IPv6) > 0
}

type Route struct {
	Gateway   string `json:"gateway"`
	Interface string `json:"interface"`
}

type Proxy struct {
	HTTP          string            `json:"http,omitempty"`
	HTTPS         string            `json:"https,omitempty"`
	SOCKS         string            `json:"socks,omitempty"`
	PACURL        string            `json:"pac_url,omitempty"`
	AutoDiscovery bool              `json:"auto_discovery,omitempty"`
	Env           map[string]string `json:"env,omitempty"`
}

func (p Proxy) Any() bool {
	return p.HTTP != "" || p.HTTPS != "" || p.SOCKS != "" || p.PACURL != "" || p.AutoDiscovery || len(p.Env) > 0
}

type WiFi struct {
	Interface   string  `json:"interface"`
	PowerOn     bool    `json:"power_on"`
	Associated  bool    `json:"associated"`
	SignalKnown bool    `json:"signal_known"`
	RSSI        int     `json:"rssi_dbm,omitempty"`
	Noise       int     `json:"noise_dbm,omitempty"`
	Channel     int     `json:"channel,omitempty"`
	Band        string  `json:"band,omitempty"`
	WidthMHz    int     `json:"width_mhz,omitempty"`
	PHYMode     string  `json:"phy_mode,omitempty"`
	TxRateMbps  float64 `json:"tx_rate_mbps,omitempty"`
	Source      string  `json:"source"`
}

// SNR is signal minus noise in dB; 0 if noise is unknown.
func (w WiFi) SNR() int {
	if !w.SignalKnown || w.Noise == 0 {
		return 0
	}
	return w.RSSI - w.Noise
}

type VPNInfo struct {
	Active             bool     `json:"active"`
	Interfaces         []string `json:"interfaces,omitempty"`
	DefaultRouteViaVPN bool     `json:"default_route_via_vpn"`
}

// Collect gathers the snapshot. It never fails outright: anything it can't
// read is recorded in Errors so the report shows what is missing.
func Collect(ctx context.Context) Snapshot {
	s := Snapshot{OS: runtime.GOOS, Arch: runtime.GOARCH, CollectedAt: time.Now()}
	s.Hostname, _ = os.Hostname()

	kinds := platformInterfaceKinds(ctx)
	ifaces, err := collectInterfaces(kinds)
	if err != nil {
		s.Errors = append(s.Errors, "interfaces: "+err.Error())
	}
	s.Interfaces = ifaces

	var wg sync.WaitGroup
	var wifi *WiFi
	var wifiErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		wifi, wifiErr = platformWiFi(ctx, ifaces)
	}()

	r4, r6, err := platformRoutes(ctx)
	if err != nil {
		s.Errors = append(s.Errors, "routes: "+err.Error())
	}
	s.DefaultRoute, s.DefaultRoute6 = r4, r6
	switch {
	case r4 != nil:
		s.PrimaryInterface = r4.Interface
	case r6 != nil:
		s.PrimaryInterface = r6.Interface
	}

	servers, src, err := platformDNS(ctx)
	if err != nil {
		s.Errors = append(s.Errors, "dns config: "+err.Error())
	}
	s.DNSServers, s.DNSSource = servers, src

	proxy, err := platformProxy(ctx)
	if err != nil {
		s.Errors = append(s.Errors, "proxy: "+err.Error())
	}
	proxy.Env = envProxy()
	s.Proxy = proxy

	wg.Wait()
	if wifiErr != nil {
		s.Errors = append(s.Errors, "wifi: "+wifiErr.Error())
	}
	s.WiFi = wifi

	s.VPN = detectVPN(s)
	return s
}

func collectInterfaces(kinds map[string]string) ([]Interface, error) {
	nis, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Interface
	for _, ni := range nis {
		it := Interface{
			Name:    ni.Name,
			Up:      ni.Flags&net.FlagUp != 0,
			Running: ni.Flags&net.FlagRunning != 0,
			MAC:     ni.HardwareAddr.String(),
			MTU:     ni.MTU,
		}
		if ni.Flags&net.FlagLoopback != 0 {
			it.Kind = KindLoopback
		} else if k, ok := kinds[ni.Name]; ok {
			it.Kind = k
		} else {
			it.Kind = kindFromName(ni.Name)
		}
		addrs, _ := ni.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipn.IP
			switch {
			case ip.To4() != nil:
				it.IPv4 = append(it.IPv4, ip.String())
			case ip.IsLinkLocalUnicast():
				it.LinkLocal6 = true
			default:
				it.IPv6 = append(it.IPv6, ip.String())
			}
		}
		out = append(out, it)
	}
	return out, nil
}

var vpnPrefixes = []string{"utun", "tun", "tap", "wg", "ppp", "ipsec", "gpd", "tailscale", "zt", "nordlynx", "proton", "cscotun"}

func kindFromName(name string) string {
	n := strings.ToLower(name)
	for _, p := range vpnPrefixes {
		if strings.HasPrefix(n, p) {
			return KindVPN
		}
	}
	switch {
	case strings.Contains(n, "wi-fi"), strings.Contains(n, "wireless"): // Windows names
		return KindWiFi
	case strings.HasPrefix(n, "ethernet"), strings.HasPrefix(n, "local area connection"):
		return KindEthernet
	case strings.HasPrefix(n, "lo"):
		return KindLoopback
	case strings.HasPrefix(n, "wl"):
		return KindWiFi
	case strings.HasPrefix(n, "eth"), strings.HasPrefix(n, "enp"), strings.HasPrefix(n, "eno"), strings.HasPrefix(n, "ens"):
		return KindEthernet
	case strings.HasPrefix(n, "bridge"), strings.HasPrefix(n, "br"), strings.HasPrefix(n, "docker"), strings.HasPrefix(n, "virbr"):
		return KindBridge
	}
	return KindOther
}

func detectVPN(s Snapshot) VPNInfo {
	var v VPNInfo
	kindOf := map[string]string{}
	for _, it := range s.Interfaces {
		kindOf[it.Name] = it.Kind
		// macOS keeps several utun interfaces up for system services; they
		// only have link-local IPv6. A real VPN tunnel has a routable address.
		if it.Kind == KindVPN && it.Up && (len(it.IPv4) > 0 || len(it.IPv6) > 0) {
			v.Active = true
			v.Interfaces = append(v.Interfaces, it.Name)
		}
	}
	for _, r := range []*Route{s.DefaultRoute, s.DefaultRoute6} {
		if r != nil && kindOf[r.Interface] == KindVPN {
			v.DefaultRouteViaVPN = true
			v.Active = true
		}
	}
	return v
}

var proxyEnvVars = []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"}

func envProxy() map[string]string {
	m := map[string]string{}
	for _, k := range proxyEnvVars {
		if v := os.Getenv(k); v != "" {
			m[k] = redactURL(v)
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

// redactURL strips credentials so reports never carry proxy passwords.
func redactURL(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		return s
	}
	u.User = url.User("redacted")
	return u.String()
}

// runCmd runs a command with a timeout and the C locale so output parsing
// doesn't depend on the user's language.
func runCmd(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LANG=C", "LC_ALL=C")
	out, err := cmd.Output()
	return string(out), err
}
