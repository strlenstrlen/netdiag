package snapshot

import (
	"reflect"
	"testing"
)

// Shaped like ConvertTo-Json output from Windows PowerShell 5.1, including
// a one-element list serialized as a bare object (dns) and fec0::
// placeholder servers.
const winSample = `{"proxy":{"ProxyEnable":1,"ProxyServer":"proxy.corp.example:8080","AutoConfigURL":null},
"routes":[{"DestinationPrefix":"0.0.0.0/0","NextHop":"192.168.1.1","InterfaceAlias":"Wi-Fi"},
          {"DestinationPrefix":"0.0.0.0/0","NextHop":"10.0.0.1","InterfaceAlias":"Ethernet 2"},
          {"DestinationPrefix":"::/0","NextHop":"fe80::1","InterfaceAlias":"Wi-Fi"}],
"dns":[{"InterfaceAlias":"Wi-Fi","ServerAddresses":["192.168.1.1","fec0:0:0:ffff::1"]},
       {"InterfaceAlias":"Ethernet 2","ServerAddresses":"10.0.0.53"}],
"adapters":[{"Name":"Wi-Fi","InterfaceDescription":"Intel(R) Wi-Fi 6E AX211 160MHz","PhysicalMediaType":"Native 802.11","Status":"Up"},
            {"Name":"Ethernet 2","InterfaceDescription":"Realtek USB GbE Family Controller","PhysicalMediaType":"802.3","Status":"Up"},
            {"Name":"Ethernet 3","InterfaceDescription":"WireGuard Tunnel","PhysicalMediaType":"Unspecified","Status":"Up"}]}`

func TestParseWinNet(t *testing.T) {
	w, err := parseWinNet(winSample)
	if err != nil {
		t.Fatal(err)
	}
	r4, r6 := w.routes()
	if r4 == nil || r4.Gateway != "192.168.1.1" || r4.Interface != "Wi-Fi" || r6 == nil || r6.Gateway != "fe80::1" {
		t.Errorf("routes: %+v %+v", r4, r6)
	}
	if got := w.dnsFor("Wi-Fi"); !reflect.DeepEqual(got, []string{"192.168.1.1"}) {
		t.Errorf("dns for Wi-Fi = %v", got)
	}
	if got := w.dnsFor("Ethernet 2"); !reflect.DeepEqual(got, []string{"10.0.0.53"}) {
		t.Errorf("single-value server list = %v", got)
	}
	want := map[string]string{"Wi-Fi": KindWiFi, "Ethernet 2": KindEthernet, "Ethernet 3": KindVPN}
	if got := w.kinds(); !reflect.DeepEqual(got, want) {
		t.Errorf("kinds = %v", got)
	}
	if p := w.proxy(); p.HTTP != "proxy.corp.example:8080" {
		t.Errorf("proxy = %+v", p)
	}
	single, err := parseWinNet(`{"routes":{"DestinationPrefix":"0.0.0.0/0","NextHop":"192.168.0.1","InterfaceAlias":"Ethernet"},"dns":[],"adapters":[],"proxy":null}`)
	if r, _ := single.routes(); err != nil || r == nil || r.Gateway != "192.168.0.1" {
		t.Errorf("single route as object: %v %+v", err, r)
	}
}

func TestParseNetshWLAN(t *testing.T) {
	out := `
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6E AX211 160MHz
    State                  : connected
    SSID                   : HomeNet
    Radio type             : 802.11ax
    Band                   : 5 GHz
    Channel                : 36
    Receive rate (Mbps)    : 1201
    Transmit rate (Mbps)   : 960
    Signal                 : 84%
`
	w, ok := parseNetshWLAN(out)
	if !ok || !w.Associated || w.RSSI != -58 || w.Channel != 36 || w.Band != "5 GHz" || w.TxRateMbps != 960 || w.PHYMode != "802.11ax" {
		t.Errorf("got %+v ok=%v", w, ok)
	}
	w, ok = parseNetshWLAN("    Name   : Wi-Fi\n    State  : disconnected\n")
	if !ok || w.Associated || w.SignalKnown {
		t.Errorf("disconnected: %+v", w)
	}
	if _, ok := parseNetshWLAN("    Nom    : Wi-Fi\n    État   : connecté\n"); ok {
		t.Error("non-English output should report unknown, not guess")
	}
}

func TestWindowsInterfaceNames(t *testing.T) {
	for name, want := range map[string]string{"Wi-Fi": KindWiFi, "Wi-Fi 2": KindWiFi, "Ethernet": KindEthernet, "wlan0": KindWiFi, "eth0": KindEthernet} {
		if got := kindFromName(name); got != want {
			t.Errorf("kindFromName(%q) = %s, want %s", name, got, want)
		}
	}
}
