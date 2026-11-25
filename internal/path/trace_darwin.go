//go:build darwin

package path

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

// trace sends ICMP echo requests with increasing TTLs over an unprivileged
// ICMP datagram socket. macOS delivers the routers' "time exceeded"
// replies to that socket, so no root is needed. Sequence numbers encode
// round and TTL: seq = round*64 + ttl.
func trace(ctx context.Context, dst net.IP, o Options) ([]reply, map[int]int, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP)
	if err != nil {
		return nil, nil, fmt.Errorf("opening ICMP socket: %w", err)
	}
	_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, 0x17, 1) // IP_STRIPHDR
	f := os.NewFile(uintptr(fd), "icmp-trace")
	pc, err := net.FilePacketConn(f)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	// pc works on a duplicate descriptor; fd stays valid for setting the TTL
	// until f is closed.
	defer f.Close()
	defer pc.Close()

	id := os.Getpid() & 0xffff
	token := make([]byte, 8)
	_, _ = rand.Read(token)
	maxHops := max(1, min(o.MaxHops, 63))

	var mu sync.Mutex
	sentAt := map[int]time.Time{}
	var replies []reply
	reached := 0 // lowest TTL that reached the destination
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			now := time.Now()
			if err != nil {
				return
			}
			seq, final, ok := parse(buf[:n], dst, id, token)
			if !ok {
				continue
			}
			mu.Lock()
			if at, ok := sentAt[seq]; ok {
				delete(sentAt, seq) // count each probe once
				ttl := seq % 64
				r := reply{ttl: ttl, from: from.(*net.UDPAddr).IP.String(), rtt: float64(now.Sub(at).Microseconds()) / 1000, final: final}
				replies = append(replies, r)
				if final && (reached == 0 || ttl < reached) {
					reached = ttl
				}
			}
			mu.Unlock()
		}
	}()

	sent := map[int]int{}
	dstAddr := &net.UDPAddr{IP: dst}
	for round := 0; round < o.Rounds && ctx.Err() == nil; round++ {
		if o.Progress != nil {
			o.Progress(fmt.Sprintf("Tracing the path… round %d of %d", round+1, o.Rounds))
		}
		mu.Lock()
		limit := maxHops
		if reached > 0 {
			limit = reached
		}
		mu.Unlock()
		for ttl := 1; ttl <= limit; ttl++ {
			if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl); err != nil {
				return nil, nil, fmt.Errorf("setting TTL: %w", err)
			}
			seq := round*64 + ttl
			mu.Lock()
			sentAt[seq] = time.Now()
			mu.Unlock()
			sent[ttl]++
			_, _ = pc.WriteTo(echo(id, seq, token), dstAddr)
			time.Sleep(10 * time.Millisecond)
		}
		// Give this round's replies time to arrive before the next one.
		time.Sleep(600 * time.Millisecond)
	}
	time.Sleep(400 * time.Millisecond)
	pc.Close()
	<-readerDone
	mu.Lock()
	defer mu.Unlock()
	return replies, sent, nil
}

func echo(id, seq int, token []byte) []byte {
	b := make([]byte, 8, 40)
	b[0] = 8
	binary.BigEndian.PutUint16(b[4:], uint16(id))
	binary.BigEndian.PutUint16(b[6:], uint16(seq))
	b = append(b, token...)
	b = append(b, make([]byte, 24)...)
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	binary.BigEndian.PutUint16(b[2:], ^uint16(s))
	return b
}

// parse returns the probe sequence number an ICMP message answers: an echo
// reply from the destination (final) or a time-exceeded / unreachable
// message quoting one of our probes to dst.
func parse(b []byte, dst net.IP, id int, token []byte) (seq int, final, ok bool) {
	if len(b) >= 20 && b[0]>>4 == 4 { // IP header still attached
		b = b[int(b[0]&0x0f)*4:]
	}
	if len(b) < 8 {
		return 0, false, false
	}
	switch b[0] {
	case 0: // echo reply
		if len(b) >= 16 && bytes.Equal(b[8:16], token) {
			return int(binary.BigEndian.Uint16(b[6:])), true, true
		}
	case 11, 3: // time exceeded, destination unreachable
		inner := b[8:]
		if len(inner) < 20 || inner[0]>>4 != 4 {
			return 0, false, false
		}
		ihl := int(inner[0]&0x0f) * 4
		if len(inner) < ihl+8 || !net.IP(inner[16:20]).Equal(dst) {
			return 0, false, false
		}
		q := inner[ihl:]
		if q[0] != 8 || int(binary.BigEndian.Uint16(q[4:])) != id {
			return 0, false, false
		}
		return int(binary.BigEndian.Uint16(q[6:])), b[0] == 3, true
	}
	return 0, false, false
}
