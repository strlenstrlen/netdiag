//go:build darwin || linux

package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Ping sends ICMP echo requests over an unprivileged datagram ICMP socket.
// macOS allows these for every user; Linux allows them when the user's group
// is in net.ipv4.ping_group_range (the default on most desktop distros).
// When the OS refuses, the result is marked Unavailable rather than failed.
//
// Requests go out on a fixed schedule (start + n*interval) and a separate
// goroutine collects replies, so a lost packet never delays the series and
// series to different targets started together stay aligned by sequence.
func Ping(ctx context.Context, target string, count int, interval, timeout time.Duration) PingResult {
	return PingUntil(ctx, nil, target, count, interval, timeout)
}

// PingUntil is Ping that also stops sending when stop is closed. Replies
// already in flight are still collected (up to timeout after the last
// send), which matters under load, when late replies are the measurement.
func PingUntil(ctx context.Context, stop <-chan struct{}, target string, count int, interval, timeout time.Duration) PingResult {
	res := PingResult{Target: target, Method: "icmp"}
	host, zone, _ := strings.Cut(target, "%")
	ip := net.ParseIP(host)
	if ip == nil {
		res.Err = "not an IP address"
		return res
	}
	v6 := ip.To4() == nil

	pc, err := openICMP(v6)
	if err != nil {
		res.Unavailable = true
		res.Err = err.Error()
		return res
	}
	defer pc.Close()

	dst := &net.UDPAddr{IP: ip, Zone: zone}
	id := os.Getpid() & 0xffff
	token := make([]byte, 8)
	_, _ = rand.Read(token)

	var mu sync.Mutex
	sentAt := make([]time.Time, count+1)
	rtt := make([]float64, count+1)
	got := make([]bool, count+1)
	replies := make(chan struct{}, count)
	readerDone := make(chan struct{})

	go func() {
		defer close(readerDone)
		buf := make([]byte, 1500)
		for {
			n, _, err := pc.ReadFrom(buf)
			now := time.Now()
			if err != nil {
				return // socket closed by the sender side
			}
			seq, ok := parseEchoReply(buf[:n], v6, token)
			if !ok || seq < 1 || seq > count {
				continue
			}
			mu.Lock()
			fresh := !sentAt[seq].IsZero() && !got[seq] && now.Sub(sentAt[seq]) <= timeout
			if fresh {
				got[seq] = true
				rtt[seq] = ms(now.Sub(sentAt[seq]))
			}
			mu.Unlock()
			if fresh {
				replies <- struct{}{}
			}
		}
	}()

	start := time.Now()
	sent := 0
	var lastSend time.Time
	for seq := 1; seq <= count; seq++ {
		if !sleepStop(ctx, stop, time.Until(start.Add(time.Duration(seq-1)*interval))) {
			break
		}
		now := time.Now()
		mu.Lock()
		sentAt[seq] = now
		mu.Unlock()
		lastSend = now
		sent++
		if _, err := pc.WriteTo(echoRequest(v6, id, seq, token), dst); err != nil {
			res.Err = err.Error()
		}
	}

	// Wait for outstanding replies, up to the timeout after the last send.
	received := 0
	wait := time.NewTimer(time.Until(lastSend.Add(timeout)))
	defer wait.Stop()
collect:
	for received < sent {
		select {
		case <-replies:
			received++
		case <-wait.C:
			break collect
		case <-ctx.Done():
			break collect
		}
	}
	pc.Close()
	<-readerDone

	mu.Lock()
	defer mu.Unlock()
	for seq := 1; seq <= sent; seq++ {
		s := Sample{Seq: seq, AtMs: ms(sentAt[seq].Sub(start))}
		if got[seq] {
			s.RTTMs = rtt[seq]
		} else {
			s.Lost = true
		}
		res.Samples = append(res.Samples, s)
	}
	res.finalize()
	return res
}

func openICMP(v6 bool) (net.PacketConn, error) {
	family, proto := syscall.AF_INET, syscall.IPPROTO_ICMP
	var bindAddr syscall.Sockaddr = &syscall.SockaddrInet4{}
	if v6 {
		family, proto = syscall.AF_INET6, syscall.IPPROTO_ICMPV6
		bindAddr = &syscall.SockaddrInet6{}
	}
	fd, err := syscall.Socket(family, syscall.SOCK_DGRAM, proto)
	if err != nil {
		return nil, &os.SyscallError{Syscall: "unprivileged ICMP not permitted: socket", Err: err}
	}
	if runtime.GOOS == "darwin" && !v6 {
		// IP_STRIPHDR: deliver replies without the IP header.
		_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, 0x17, 1)
	}
	if err := syscall.Bind(fd, bindAddr); err != nil {
		syscall.Close(fd)
		return nil, &os.SyscallError{Syscall: "binding ICMP socket", Err: err}
	}
	f := os.NewFile(uintptr(fd), "icmp")
	pc, err := net.FilePacketConn(f)
	f.Close()
	return pc, err
}

func echoRequest(v6 bool, id, seq int, token []byte) []byte {
	b := make([]byte, 8, 8+32)
	b[0] = 8 // echo request
	if v6 {
		b[0] = 128
	}
	binary.BigEndian.PutUint16(b[4:], uint16(id))
	binary.BigEndian.PutUint16(b[6:], uint16(seq))
	b = append(b, token...)
	b = append(b, make([]byte, 24)...)
	if !v6 { // the kernel fills in the ICMPv6 checksum
		binary.BigEndian.PutUint16(b[2:], checksum(b))
	}
	return b
}

// parseEchoReply returns the sequence number of an echo reply carrying our
// token. It matches on the token rather than the ICMP ID because Linux
// rewrites the ID on ping sockets, and macOS delivers every ICMP reply to
// every ICMP socket in the process.
func parseEchoReply(b []byte, v6 bool, token []byte) (int, bool) {
	if !v6 && len(b) >= 20 && b[0]>>4 == 4 { // IP header still attached
		b = b[int(b[0]&0x0f)*4:]
	}
	if len(b) < 16 {
		return 0, false
	}
	want := byte(0)
	if v6 {
		want = 129
	}
	if b[0] != want || !bytes.Equal(b[8:16], token) {
		return 0, false
	}
	return int(binary.BigEndian.Uint16(b[6:])), true
}

func checksum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}
