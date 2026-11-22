package dnsttclient

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
	"www.bamsoftware.com/git/dnstt.git/dns"
)

func allPackets(buf []byte) ([][]byte, error) {
	var packets [][]byte
	r := bytes.NewReader(buf)
	for {
		p, err := nextPacket(r)
		if err != nil {
			return packets, err
		}
		packets = append(packets, p)
	}
}

func packetsEqual(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func TestNextPacket(t *testing.T) {
	for _, test := range []struct {
		input   string
		packets [][]byte
		err     error
	}{
		{"", [][]byte{}, io.EOF},
		{"\x00", [][]byte{}, io.ErrUnexpectedEOF},
		{"\x00\x00", [][]byte{{}}, io.EOF},
		{"\x00\x00\x00", [][]byte{{}}, io.ErrUnexpectedEOF},
		{"\x00\x01", [][]byte{}, io.ErrUnexpectedEOF},
		{"\x00\x05hello\x00\x05world", [][]byte{[]byte("hello"), []byte("world")}, io.EOF},
	} {
		packets, err := allPackets([]byte(test.input))
		if !packetsEqual(packets, test.packets) || err != test.err {
			t.Errorf("%x\nreturned %x %v\nexpected %x %v",
				test.input, packets, err, test.packets, test.err)
		}
	}
}

// A 1232-byte advertised envelope stalled real recursive-resolver sessions even
// with the server MTU set to 1232. Keep the upstream client's 4096-byte envelope.
func TestQueryAdvertisesUpstreamReceiveCapacity(t *testing.T) {
	receiver, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sender, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	client := DNSPacketConn{domain: dns.Name{[]byte("t"), []byte("example"), []byte("com")}}
	if err := client.send(sender, []byte("payload"), receiver.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	receiver.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4096)
	n, _, err := receiver.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	query, err := dns.MessageFromWireFormat(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if len(query.Additional) != 1 || query.Additional[0].Type != dns.RRTypeOPT || query.Additional[0].Class != 4096 {
		t.Fatalf("unexpected EDNS envelope: %+v", query.Additional)
	}
}
