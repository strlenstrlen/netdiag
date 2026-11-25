package snapshot

// Windows parsers. No build tag, so their tests run on any platform.

import (
	"bytes"
	"encoding/json"
	"net"
	"strconv"
	"strings"
)

// winPowerShell gathers routes, DNS servers, adapter types and proxy
// settings in one call. PowerShell objects serialize the same in every
// display language, unlike ipconfig or netsh text.
const winPowerShell = `$ErrorActionPreference='SilentlyContinue'
$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' | Sort-Object { $_.RouteMetric + $_.InterfaceMetric } | Select-Object DestinationPrefix,NextHop,InterfaceAlias
$d = Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses.Count -gt 0 } | Select-Object InterfaceAlias,ServerAddresses
$a = Get-NetAdapter | Select-Object Name,InterfaceDescription,PhysicalMediaType,Status
$p = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object ProxyEnable,ProxyServer,AutoConfigURL
@{routes=@($r); dns=@($d); adapters=@($a); proxy=$p} | ConvertTo-Json -Depth 4 -Compress`

// list accepts a JSON array or a single object (PowerShell unwraps
// one-element arrays in some versions).
type list[T any] []T

func (l *list[T]) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '{' {
		var one T
		if err := json.Unmarshal(b, &one); err != nil {
			return err
		}
		*l = list[T]{one}
		return nil
	}
	var many []T
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*l = many
	return nil
}

type winNet struct {
	Routes list[struct {
		DestinationPrefix string
		NextHop           string
		InterfaceAlias    string
	}] `json:"routes"`
	DNS list[struct {
		InterfaceAlias  string
		ServerAddresses list[string]
	}] `json:"dns"`
	Adapters list[struct {
		Name                 string
		InterfaceDescription string
		PhysicalMediaType    string
		Status               string
	}] `json:"adapters"`
	Proxy *struct {
		ProxyEnable   int
		ProxyServer   string
		AutoConfigURL string
	} `json:"proxy"`
}

func parseWinNet(out string) (winNet, error) {
	var w winNet
	err := json.Unmarshal([]byte(strings.TrimSpace(out)), &w)
	return w, err
}

func (w winNet) routes() (r4, r6 *Route) {
	for _, r := range w.Routes {
		route := &Route{Gateway: r.NextHop, Interface: r.InterfaceAlias}
		switch {
		case r.DestinationPrefix == "0.0.0.0/0" && r4 == nil && r.NextHop != "0.0.0.0":
			r4 = route
		case r.DestinationPrefix == "::/0" && r6 == nil && r.NextHop != "::":
			r6 = route
		}
	}
	return
}

// dnsFor returns the DNS servers of the given interface, or of every
// interface if it has none. Windows lists site-local fec0:: placeholders
// on interfaces without IPv6 DNS; those are dropped.
func (w winNet) dnsFor(alias string) []string {
	collect := func(match func(string) bool) []string {
		var out []string
		seen := map[string]bool{}
		for _, d := range w.DNS {
			if !match(d.InterfaceAlias) {
				continue
			}
			for _, s := range d.ServerAddresses {
				if strings.HasPrefix(strings.ToLower(s), "fec0:") || net.ParseIP(s) == nil || seen[s] {
					continue
				}
				seen[s] = true
				out = append(out, s)
			}
		}
		return out
	}
	if s := collect(func(a string) bool { return a == alias }); len(s) > 0 {
		return s
	}
	return collect(func(a string) bool { return !strings.HasPrefix(strings.ToLower(a), "loopback") })
}

func (w winNet) kinds() map[string]string {
	m := map[string]string{}
	for _, a := range w.Adapters {
		desc := strings.ToLower(a.InterfaceDescription)
		media := strings.ToLower(a.PhysicalMediaType)
		switch {
		case strings.Contains(desc, "vpn"), strings.Contains(desc, "tap-"), strings.Contains(desc, "wireguard"),
			strings.Contains(desc, "anyconnect"), strings.Contains(desc, "tunnel"), strings.Contains(desc, "wintun"):
			m[a.Name] = KindVPN
		case strings.Contains(media, "802.11"), strings.Contains(desc, "wireless"), strings.Contains(desc, "wi-fi"):
			m[a.Name] = KindWiFi
		case strings.Contains(desc, "hyper-v"), strings.Contains(desc, "virtual"):
			m[a.Name] = KindBridge
		case strings.Contains(media, "802.3"):
			m[a.Name] = KindEthernet
		}
	}
	return m
}

func (w winNet) proxy() Proxy {
	var p Proxy
	if w.Proxy == nil {
		return p
	}
	if w.Proxy.ProxyEnable == 1 && w.Proxy.ProxyServer != "" {
		p.HTTP, p.HTTPS = w.Proxy.ProxyServer, w.Proxy.ProxyServer
	}
	p.PACURL = w.Proxy.AutoConfigURL
	return p
}

// parseNetshWLAN reads `netsh wlan show interfaces`. Its labels are
// translated, so this only works on English Windows; elsewhere it returns
// ok=false and the caller reports signal strength as unavailable.
func parseNetshWLAN(out string) (w WiFi, ok bool) {
	kv := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if _, dup := kv[k]; !dup { // first interface only
			kv[k] = strings.TrimSpace(v)
		}
	}
	state, known := kv["state"]
	if !known {
		return w, false
	}
	w.Interface = kv["name"]
	w.PowerOn = true
	w.Associated = strings.EqualFold(state, "connected")
	w.Source = "netsh wlan (signal estimated from %)"
	if !w.Associated {
		return w, true
	}
	if pct, err := strconv.Atoi(strings.TrimSuffix(kv["signal"], "%")); err == nil {
		// Windows reports 0–100%; the usual mapping is linear from
		// -100 dBm (0%) to -50 dBm (100%).
		w.RSSI = pct/2 - 100
		w.SignalKnown = true
	}
	w.Channel, _ = strconv.Atoi(kv["channel"])
	w.PHYMode = kv["radio type"]
	if b := kv["band"]; b != "" {
		w.Band = b
	} else if w.Channel > 0 {
		switch {
		case w.Channel <= 14:
			w.Band = "2.4 GHz"
		default:
			w.Band = "5 GHz"
		}
	}
	w.TxRateMbps, _ = strconv.ParseFloat(kv["transmit rate (mbps)"], 64)
	return w, true
}
