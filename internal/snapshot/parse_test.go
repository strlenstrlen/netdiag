package snapshot

import (
	"reflect"
	"testing"
)

func TestParseRouteGet(t *testing.T) {
	out := `   route to: default
destination: default
       mask: default
    gateway: 192.168.0.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
`
	got := parseRouteGet(out)
	if got == nil || got.Gateway != "192.168.0.1" || got.Interface != "en0" {
		t.Fatalf("got %+v", got)
	}
	if parseRouteGet("route: writing to routing socket: not in table") != nil {
		t.Error("missing route should parse to nil")
	}
}

func TestParseScutilDNS(t *testing.T) {
	out := `DNS configuration

resolver #1
  nameserver[0] : 192.168.0.1
  nameserver[1] : 198.51.100.53
  if_index : 14 (en0)
  flags    : Request A records

resolver #2
  domain   : local
  options  : mdns

resolver #3
  domain   : corp.example
  nameserver[0] : 10.0.0.53

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.168.0.1
  nameserver[1] : 198.51.100.53
  nameserver[2] : 9.9.9.9
`
	got := parseScutilDNS(out)
	want := []string{"192.168.0.1", "198.51.100.53"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseScutilProxy(t *testing.T) {
	out := `<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
  }
  HTTPEnable : 1
  HTTPPort : 8080
  HTTPProxy : proxy.corp.example
  HTTPSEnable : 0
  ProxyAutoConfigEnable : 1
  ProxyAutoConfigURLString : http://wpad.corp.example/proxy.pac
}`
	p := parseScutilProxy(out)
	if p.HTTP != "proxy.corp.example:8080" || p.HTTPS != "" || p.PACURL != "http://wpad.corp.example/proxy.pac" {
		t.Errorf("got %+v", p)
	}
	if parseScutilProxy("<dictionary> {\n  FTPPassive : 1\n}").Any() {
		t.Error("no proxy should report Any() == false")
	}
}

func TestParseHardwarePorts(t *testing.T) {
	out := `
Hardware Port: Ethernet Adapter (en4)
Device: en4
Ethernet Address: 02:00:00:00:00:01

Hardware Port: Thunderbolt Bridge
Device: bridge0
Ethernet Address: 36:33:ee:2b:1f:00

Hardware Port: Wi-Fi
Device: en0
Ethernet Address: 02:00:00:00:00:02
`
	got := parseHardwarePorts(out)
	want := map[string]string{"en4": KindEthernet, "bridge0": KindBridge, "en0": KindWiFi}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseProcRoute(t *testing.T) {
	content := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0100A8C0	0003	0	0	100	00000000	0	0	0
wlan0	00000000	0101A8C0	0003	0	0	600	00000000	0	0	0
eth0	0000A8C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
`
	got := parseProcRoute(content)
	if got == nil || got.Gateway != "192.168.0.1" || got.Interface != "eth0" {
		t.Errorf("got %+v", got)
	}
}

func TestParseProcIPv6Route(t *testing.T) {
	content := `00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 wlan0
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 wlan0
`
	got := parseProcIPv6Route(content)
	if got == nil || got.Gateway != "fe80::1" || got.Interface != "wlan0" {
		t.Errorf("got %+v", got)
	}
}

func TestParseResolvectlDNS(t *testing.T) {
	out := `Global: 1.1.1.1#cloudflare-dns.com
Link 2 (eth0): 192.168.1.1 fe80::1%2
Link 3 (wlan0):
`
	got := parseResolvectlDNS(out)
	want := []string{"1.1.1.1", "192.168.1.1", "fe80::1%2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseProcWireless(t *testing.T) {
	content := `Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE
 face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22
wlan0: 0000   54.  -56.  -256        0      0      0      0     12        0
`
	rssi, noise, ok := parseProcWireless(content, "wlan0")
	if !ok || rssi != -56 || noise != 0 {
		t.Errorf("got rssi=%d noise=%d ok=%v", rssi, noise, ok)
	}
	if _, _, ok := parseProcWireless(content, "wlan1"); ok {
		t.Error("unknown interface should not parse")
	}
}

func TestSelfAssignedAndVPN(t *testing.T) {
	it := Interface{Name: "en0", Up: true, IPv4: []string{"169.254.10.2"}}
	if !it.SelfAssignedOnly() || it.Usable() {
		t.Error("169.254 address should be self-assigned and unusable")
	}
	s := Snapshot{
		Interfaces: []Interface{
			{Name: "utun0", Kind: KindVPN, Up: true, LinkLocal6: true}, // macOS system tunnel
			{Name: "utun5", Kind: KindVPN, Up: true, IPv4: []string{"10.8.0.2"}},
		},
		DefaultRoute: &Route{Gateway: "10.8.0.1", Interface: "utun5"},
	}
	v := detectVPN(s)
	if !v.Active || !v.DefaultRouteViaVPN || len(v.Interfaces) != 1 || v.Interfaces[0] != "utun5" {
		t.Errorf("got %+v", v)
	}
}

func TestRedactURL(t *testing.T) {
	if got := redactURL("http://alice:s3cret@proxy:3128"); got != "http://redacted@proxy:3128" {
		t.Errorf("got %q", got)
	}
}
