//go:build darwin && cgo

package snapshot

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework CoreWLAN -framework Foundation
#import <CoreWLAN/CoreWLAN.h>
#include <string.h>

typedef struct {
	int ok;
	int powerOn;
	int associated;
	long rssi;
	long noise;
	double txRate;
	long channel;
	int band;
	int width;
	int phyMode;
	char ifname[32];
} nd_wifi;

// Reads the default Wi-Fi interface via CoreWLAN. Signal, noise, channel
// and rate don't need Location Services; SSID/BSSID do, so we skip them.
static nd_wifi nd_wifi_info(void) {
	nd_wifi r;
	memset(&r, 0, sizeof(r));
	@autoreleasepool {
		CWInterface *iface = [[CWWiFiClient sharedWiFiClient] interface];
		if (iface == nil) return r;
		r.ok = 1;
		NSString *name = [iface interfaceName];
		if (name != nil) strncpy(r.ifname, [name UTF8String], sizeof(r.ifname) - 1);
		r.powerOn = [iface powerOn] ? 1 : 0;
		CWChannel *ch = [iface wlanChannel];
		r.rssi = (long)[iface rssiValue];
		r.noise = (long)[iface noiseMeasurement];
		r.txRate = [iface transmitRate];
		r.associated = (ch != nil && r.rssi != 0) ? 1 : 0;
		if (ch != nil) {
			r.channel = (long)[ch channelNumber];
			r.band = (int)[ch channelBand];
			r.width = (int)[ch channelWidth];
		}
		r.phyMode = (int)[iface activePHYMode];
	}
	return r;
}
*/
import "C"

import (
	"context"
	"errors"
)

func platformWiFi(ctx context.Context, ifaces []Interface) (*WiFi, error) {
	r := C.nd_wifi_info()
	if r.ok == 0 {
		return nil, nil // no Wi-Fi hardware
	}
	w := &WiFi{
		Interface:  C.GoString(&r.ifname[0]),
		PowerOn:    r.powerOn != 0,
		Associated: r.associated != 0,
		Source:     "CoreWLAN",
	}
	if !w.PowerOn || !w.Associated {
		return w, nil
	}
	w.SignalKnown = true
	w.RSSI = int(r.rssi)
	w.Noise = int(r.noise)
	w.TxRateMbps = float64(r.txRate)
	w.Channel = int(r.channel)
	w.Band = map[int]string{1: "2.4 GHz", 2: "5 GHz", 3: "6 GHz"}[int(r.band)]
	w.WidthMHz = map[int]int{1: 20, 2: 40, 3: 80, 4: 160}[int(r.width)]
	w.PHYMode = map[int]string{1: "802.11a", 2: "802.11b", 3: "802.11g", 4: "802.11n", 5: "802.11ac", 6: "802.11ax", 7: "802.11be"}[int(r.phyMode)]
	if w.RSSI == 0 {
		return w, errors.New("CoreWLAN returned no signal reading")
	}
	return w, nil
}
