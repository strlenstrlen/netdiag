package snapshot

// Parsers for OS command output and /proc files. They have no build tags so
// their tests run on any platform.

import (
	"bufio"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
)

// parseRouteGet parses macOS `route -n get default` output.
func parseRouteGet(out string) *Route {
	var r Route
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "gateway":
			r.Gateway = strings.TrimSpace(v)
		case "interface":
			r.Interface = strings.TrimSpace(v)
		}
	}
	if r.Gateway == "" && r.Interface == "" {
		return nil
	}
	return &r
}

// parseScutilDNS returns the nameservers of the default (unscoped, no
// domain) resolvers from macOS `scutil --dns`. It stops at the scoped
// section, which repeats per-interface servers.
func parseScutilDNS(out string) []string {
	var servers []string
	seen := map[string]bool{}
	var block []string
	flush := func() {
		hasDomain := false
		var ns []string
		for _, l := range block {
			k, v, ok := strings.Cut(l, ":")
			if !ok {
				continue
			}
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			if k == "domain" {
				hasDomain = true
			}
			if strings.HasPrefix(k, "nameserver[") {
				ns = append(ns, v)
			}
		}
		if !hasDomain {
			for _, n := range ns {
				if !seen[n] {
					seen[n] = true
					servers = append(servers, n)
				}
			}
		}
		block = nil
	}
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "DNS configuration (for scoped queries)") {
			break
		}
		if strings.HasPrefix(t, "resolver #") {
			flush()
			continue
		}
		if t != "" {
			block = append(block, t)
		}
	}
	flush()
	return servers
}

// parseScutilProxy parses macOS `scutil --proxy`.
func parseScutilProxy(out string) Proxy {
	kv := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " : ")
		if ok {
			kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	hp := func(prefix string) string {
		if kv[prefix+"Enable"] != "1" || kv[prefix+"Proxy"] == "" {
			return ""
		}
		if p := kv[prefix+"Port"]; p != "" {
			return net.JoinHostPort(kv[prefix+"Proxy"], p)
		}
		return kv[prefix+"Proxy"]
	}
	p := Proxy{HTTP: hp("HTTP"), HTTPS: hp("HTTPS"), SOCKS: hp("SOCKS")}
	if kv["ProxyAutoConfigEnable"] == "1" {
		p.PACURL = kv["ProxyAutoConfigURLString"]
		if p.PACURL == "" {
			p.PACURL = "(enabled, no URL)"
		}
	}
	p.AutoDiscovery = kv["ProxyAutoDiscoveryEnable"] == "1"
	return p
}

// parseHardwarePorts maps device names to kinds from macOS
// `networksetup -listallhardwareports`.
func parseHardwarePorts(out string) map[string]string {
	m := map[string]string{}
	var port string
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(line, "Hardware Port: "); ok {
			port = strings.ToLower(v)
			continue
		}
		dev, ok := strings.CutPrefix(line, "Device: ")
		if !ok || port == "" {
			continue
		}
		switch {
		case strings.Contains(port, "wi-fi"), strings.Contains(port, "airport"):
			m[dev] = KindWiFi
		case strings.Contains(port, "bridge"):
			m[dev] = KindBridge
		case strings.Contains(port, "bluetooth"), strings.Contains(port, "iphone"), strings.Contains(port, "ipad"):
			m[dev] = KindOther
		default:
			m[dev] = KindEthernet
		}
		port = ""
	}
	return m
}

// parseProcRoute finds the IPv4 default route in Linux /proc/net/route.
func parseProcRoute(content string) *Route {
	var best *Route
	bestMetric := -1
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 8 || f[0] == "Iface" {
			continue
		}
		if f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		gw, err := hex.DecodeString(f[2])
		if err != nil || len(gw) != 4 {
			continue
		}
		metric, _ := strconv.Atoi(f[6])
		if best == nil || metric < bestMetric {
			ip := net.IPv4(gw[3], gw[2], gw[1], gw[0]) // stored little-endian
			best = &Route{Gateway: ip.String(), Interface: f[0]}
			bestMetric = metric
		}
	}
	return best
}

// parseProcIPv6Route finds the IPv6 default route in /proc/net/ipv6_route.
func parseProcIPv6Route(content string) *Route {
	zero := strings.Repeat("0", 32)
	var best *Route
	var bestMetric uint64
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[0] != zero || f[1] != "00" || f[4] == zero {
			continue
		}
		if f[9] == "lo" {
			continue
		}
		b, err := hex.DecodeString(f[4])
		if err != nil || len(b) != 16 {
			continue
		}
		metric, _ := strconv.ParseUint(f[5], 16, 64)
		if best == nil || metric < bestMetric {
			best = &Route{Gateway: net.IP(b).String(), Interface: f[9]}
			bestMetric = metric
		}
	}
	return best
}

// parseResolvConf returns nameserver lines from /etc/resolv.conf.
func parseResolvConf(content string) []string {
	var out []string
	for _, line := range strings.Split(content, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			out = append(out, f[1])
		}
	}
	return out
}

// parseResolvectlDNS parses `resolvectl dns` output, e.g.
// "Global: 1.1.1.1" and "Link 2 (eth0): 192.168.1.1 fe80::1".
func parseResolvectlDNS(out string) []string {
	var servers []string
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		_, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		// IPv6 addresses contain colons, so split on the first ": " instead.
		if i := strings.Index(line, ": "); i >= 0 {
			v = line[i+2:]
		}
		for _, s := range strings.Fields(v) {
			s = strings.SplitN(s, "#", 2)[0] // drop "#servername" suffixes
			if net.ParseIP(strings.SplitN(s, "%", 2)[0]) != nil && !seen[s] {
				seen[s] = true
				servers = append(servers, s)
			}
		}
	}
	return servers
}

// parseProcWireless reads Linux /proc/net/wireless. Signal and noise are
// dBm when negative; noise of -256 means the driver doesn't report it.
func parseProcWireless(content, iface string) (rssi, noise int, ok bool) {
	for _, line := range strings.Split(content, "\n") {
		name, rest, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found || name != iface {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 4 {
			return 0, 0, false
		}
		lvl, err := strconv.ParseFloat(strings.TrimSuffix(f[2], "."), 64)
		if err != nil {
			return 0, 0, false
		}
		nz, _ := strconv.ParseFloat(strings.TrimSuffix(f[3], "."), 64)
		if nz <= -256 || nz >= 0 {
			nz = 0
		}
		return int(lvl), int(nz), lvl < 0
	}
	return 0, 0, false
}
