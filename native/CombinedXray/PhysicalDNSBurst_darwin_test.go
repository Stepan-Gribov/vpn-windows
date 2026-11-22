package libXray

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// DNS callers often start many lookups together when an app opens or a network
// returns. A concurrency bound must queue requests, not reset accepted sockets.
func TestPhysicalDNSQueuesConcurrentLookups(t *testing.T) {
	iface, address := physicalDNSFixtureInterface(t)
	upstream, err := net.ListenPacket("udp4", net.JoinHostPort(address, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	release := make(chan struct{})
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, peer, err := upstream.ReadFrom(buffer)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			reply := append([]byte(nil), buffer[:n]...)
			reply[2], reply[3] = 0x81, 0x80
			reply[6], reply[7] = 0, 1
			reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 7)
			<-release
			_, _ = upstream.WriteTo(reply, peer)
		}
	}()
	resolvers, _ := json.Marshal([]string{upstream.LocalAddr().String()})
	port := KindlyPhysicalDNSStart(iface, string(resolvers))
	if port <= 0 {
		t.Fatal("bridge start failed")
	}
	defer KindlyPhysicalDNSStop()
	const count = 48
	start := make(chan struct{})
	results := make(chan error, count)
	for i := 0; i < count; i++ {
		go func(id uint16) {
			<-start
			c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
			if err != nil {
				results <- err
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(4 * time.Second))
			query := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}
			binary.BigEndian.PutUint16(query, id)
			frame := make([]byte, 2+len(query))
			binary.BigEndian.PutUint16(frame, uint16(len(query)))
			copy(frame[2:], query)
			if _, err = c.Write(frame); err != nil {
				results <- err
				return
			}
			var size [2]byte
			if _, err = io.ReadFull(c, size[:]); err != nil {
				results <- err
				return
			}
			reply := make([]byte, int(binary.BigEndian.Uint16(size[:])))
			if _, err = io.ReadFull(c, reply); err != nil {
				results <- err
				return
			}
			if len(reply) < 12 || binary.BigEndian.Uint16(reply) != id || reply[3]&15 != 0 || binary.BigEndian.Uint16(reply[6:8]) != 1 {
				results <- fmt.Errorf("invalid reply for %d", id)
				return
			}
			results <- nil
		}(uint16(i + 1))
	}
	close(start)
	// Hold the first upstream response while a normal startup burst is accepted.
	time.Sleep(250 * time.Millisecond)
	close(release)
	failed := 0
	for i := 0; i < count; i++ {
		if err := <-results; err != nil {
			failed++
			t.Log(err)
		}
	}
	if failed != 0 {
		t.Fatalf("%d/%d DNS lookups were dropped during a startup burst", failed, count)
	}
}

func TestPhysicalDNSStopCancelsQueuedClients(t *testing.T) {
	iface, _ := physicalDNSFixtureInterface(t)
	port := KindlyPhysicalDNSStart(iface, `["1.1.1.1:53"]`)
	if port <= 0 {
		t.Fatal("bridge start failed")
	}
	defer KindlyPhysicalDNSStop()
	var clients []net.Conn
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()
	for i := 0; i < 32; i++ {
		c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
	}
	stopped := make(chan struct{})
	go func() { KindlyPhysicalDNSStop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("DNS shutdown blocked behind queued clients")
	}
}

func physicalDNSFixtureInterface(t *testing.T) (string, string) {
	t.Helper()
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || !(strings.HasPrefix(iface.Name, "en") || strings.HasPrefix(iface.Name, "pdp_ip")) {
			continue
		}
		addresses, _ := iface.Addrs()
		for _, address := range addresses {
			ip, _, _ := net.ParseCIDR(address.String())
			if ip.To4() != nil {
				return iface.Name, ip.String()
			}
		}
	}
	t.Skip("No physical IPv4 interface for bound DNS fixture")
	return "", ""
}
