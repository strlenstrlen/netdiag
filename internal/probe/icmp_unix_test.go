//go:build darwin || linux

package probe

import "testing"

func TestChecksum(t *testing.T) {
	// Echo request, id 1, seq 1, no payload: checksum is 0xf7fd.
	b := []byte{8, 0, 0, 0, 0, 1, 0, 1}
	if got := checksum(b); got != 0xf7fd {
		t.Errorf("checksum = %#x", got)
	}
}

func TestEchoReplyMatching(t *testing.T) {
	token := []byte("abcdefgh")
	req := echoRequest(false, 7, 3, token)
	reply := append([]byte{}, req...)
	reply[0] = 0 // echo reply
	if seq, ok := parseEchoReply(reply, false, token); !ok || seq != 3 {
		t.Errorf("own reply: seq=%d ok=%v", seq, ok)
	}
	if _, ok := parseEchoReply(reply, false, []byte("zzzzzzzz")); ok {
		t.Error("another socket's token should not match")
	}
	if _, ok := parseEchoReply(req, false, token); ok {
		t.Error("an echo request is not a reply")
	}
	// Same reply with a 20-byte IPv4 header in front (macOS without STRIPHDR).
	withHdr := append(append([]byte{0x45}, make([]byte, 19)...), reply...)
	if seq, ok := parseEchoReply(withHdr, false, token); !ok || seq != 3 {
		t.Error("should strip an IPv4 header")
	}
}
