//go:build windows

package probe

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Windows ping uses IcmpSendEcho from iphlpapi.dll, which needs no admin
// rights. Each request blocks, so requests run on their own goroutines to
// keep the send schedule. IPv6 (Icmp6SendEcho2) isn't implemented yet.

var (
	iphlpapi        = syscall.NewLazyDLL("iphlpapi.dll")
	icmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	icmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	icmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
)

func Ping(ctx context.Context, target string, count int, interval, timeout time.Duration) PingResult {
	return PingUntil(ctx, nil, target, count, interval, timeout)
}

func PingUntil(ctx context.Context, stop <-chan struct{}, target string, count int, interval, timeout time.Duration) PingResult {
	res := PingResult{Target: target, Method: "icmp"}
	ip := net.ParseIP(target).To4()
	if ip == nil {
		res.Unavailable = true
		res.Err = "IPv6 ping isn't implemented on Windows yet"
		return res
	}
	if err := icmpSendEcho.Find(); err != nil {
		res.Unavailable = true
		res.Err = "IcmpSendEcho unavailable: " + err.Error()
		return res
	}
	dest := binary.LittleEndian.Uint32(ip) // IPAddr holds the address bytes in network order
	ms32 := uint32(max(1, timeout.Milliseconds()))

	samples := make([]Sample, count)
	var wg sync.WaitGroup
	start := time.Now()
	n := 0
	for i := range count {
		if !sleepStop(ctx, stop, time.Until(start.Add(time.Duration(i)*interval))) {
			break
		}
		n++
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := Sample{Seq: i + 1, AtMs: ms(time.Since(start)), Lost: true}
			if rtt, ok := echoOnce(dest, ms32); ok {
				s.Lost, s.RTTMs = false, rtt
			}
			samples[i] = s
		}()
	}
	wg.Wait()
	res.Samples = samples[:n]
	res.finalize()
	if res.Received == 0 && res.Sent > 0 {
		res.Err = "no reply"
	}
	return res
}

func echoOnce(dest, timeoutMs uint32) (float64, bool) {
	h, _, _ := icmpCreateFile.Call()
	if h == 0 || h == ^uintptr(0) {
		return 0, false
	}
	defer icmpCloseHandle.Call(h)
	payload := []byte("netdiag-echo-req")
	// ICMP_ECHO_REPLY (up to 40 bytes on 64-bit) + payload + 8 bytes for an ICMP error.
	reply := make([]byte, 64+len(payload)+8)
	start := time.Now()
	n, _, _ := icmpSendEcho.Call(h, uintptr(dest),
		uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)),
		0, uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(timeoutMs))
	elapsed := time.Since(start)
	if n == 0 {
		return 0, false
	}
	// The first three fields are the same on 32- and 64-bit: Address,
	// Status, RoundTripTime (milliseconds).
	status := binary.LittleEndian.Uint32(reply[4:8])
	if status != 0 { // IP_SUCCESS
		return 0, false
	}
	rtt := float64(binary.LittleEndian.Uint32(reply[8:12]))
	if rtt == 0 {
		// Windows reports whole milliseconds; use the measured time for sub-ms replies.
		rtt = round1(float64(elapsed.Microseconds()) / 1000)
	}
	return rtt, true
}
