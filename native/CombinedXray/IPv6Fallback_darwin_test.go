package libXray

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/platform"
	"golang.org/x/sys/unix"
)

// A routing blackhole is too late: the virtual TCP handshake has already won
// Happy Eyeballs. Refuse SYN before SYN-ACK, and reject QUIC without a UDP flow.
func TestDisabledIPv6RejectsBeforeHandshake(t *testing.T) {
	config := `{"log":{"loglevel":"warning"},"inbounds":[{"tag":"in_proxy","protocol":"tun","settings":{"name":"utun-ipv6-fixture","MTU":1280}}],"outbounds":[{"tag":"proxy","protocol":"freedom"},{"tag":"block","protocol":"blackhole","settings":{"response":{"type":"http"}}}],"routing":{"rules":[{"type":"field","ip":["::/0"],"outboundTag":"block"},{"type":"field","network":"tcp,udp","outboundTag":"proxy"}]}}`
	app := ipv6FallbackCore(t, config)

	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 40201)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	binary.BigEndian.PutUint32(tcp[4:8], 1)
	tcp[12], tcp[13] = 5<<4, 2
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	ipv6FallbackWrite(t, app, 6, tcp, 16)
	packet := ipv6FallbackRead(t, app)
	if packet[0]>>4 != 6 || packet[6] != 6 || len(packet) < 60 || packet[53]&4 == 0 || packet[53]&2 != 0 {
		t.Fatalf("Disabled IPv6 must receive RST, never SYN-ACK: %x", packet)
	}
	if binary.BigEndian.Uint32(packet[48:52]) != 2 {
		t.Fatal("RST did not acknowledge the original SYN")
	}
	t.Log("disabled IPv6 TCP: refused before handshake")

	udp := append(make([]byte, 8), []byte("quic-fallback-test")...)
	binary.BigEndian.PutUint16(udp[0:2], 40202)
	binary.BigEndian.PutUint16(udp[2:4], 443)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	ipv6FallbackWrite(t, app, 17, udp, 6)
	packet = ipv6FallbackRead(t, app)
	if packet[0]>>4 != 6 || packet[6] != 58 || len(packet) < 48 || packet[40] != 1 || packet[41] != 4 {
		t.Fatalf("Disabled IPv6 UDP must receive ICMPv6 port unreachable: %x", packet)
	}
	t.Log("disabled IPv6 UDP: ICMPv6 port unreachable; no tunnel/direct flow")

	tunTestTCPWrite(t, app, 1, 0, 2, nil)
	packet = ipv6FallbackRead(t, app)
	if packet[0]>>4 != 4 || packet[9] != 6 || len(packet) < 40 || packet[33]&0x12 != 0x12 {
		t.Fatalf("IPv4 fallback must still accept TCP: %x", packet)
	}
	t.Log("IPv4 fallback: handshake available")

	SetIPv6Enabled(true)
	ipv6FallbackWrite(t, app, 6, tcp, 16)
	packet = ipv6FallbackRead(t, app)
	if packet[0]>>4 != 6 || packet[6] != 6 || len(packet) < 60 || packet[53]&0x12 != 0x12 {
		t.Fatalf("Explicitly enabled IPv6 must keep its TCP listener: %x", packet)
	}
	t.Log("enabled IPv6: handshake available; existing CIDR routing remains responsible")
}

func ipv6FallbackCore(t *testing.T, config string) *os.File {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	app := os.NewFile(uintptr(fds[1]), "ipv6-fallback-packet-flow")
	t.Cleanup(func() { app.Close(); unix.Close(fds[0]) })
	t.Setenv(platform.TunFdKey, strconv.Itoa(fds[0]))
	SetIPv6Enabled(false)
	t.Cleanup(func() { SetIPv6Enabled(true) })
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	request, _ := json.Marshal(runXrayRequest{ConfigPath: path})
	raw, err := base64.StdEncoding.DecodeString(RunXray(base64.StdEncoding.EncodeToString(request)))
	if err != nil {
		t.Fatal(err)
	}
	var result callResponse
	if err := json.Unmarshal(raw, &result); err != nil || !result.Success {
		t.Fatalf("start: %s", raw)
	}
	t.Cleanup(func() { _ = unix.Shutdown(fds[1], unix.SHUT_RDWR); StopXray() })
	timer := time.AfterFunc(4*time.Second, func() { _ = unix.Shutdown(fds[1], unix.SHUT_RDWR) })
	t.Cleanup(func() { timer.Stop() })
	return app
}

func TestDisabledIPv6KeepsInterceptedDNS(t *testing.T) {
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, address, err := upstream.ReadFrom(buffer)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			reply := append([]byte(nil), buffer[:n]...)
			reply[2], reply[3], reply[6], reply[7] = 0x81, 0x80, 0, 1
			reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 7)
			_, _ = upstream.WriteTo(reply, address)
		}
	}()
	config := fmt.Sprintf(`{"log":{"loglevel":"warning"},"dns":{"queryStrategy":"UseIPv4","tag":"kindly-dns-query","servers":[{"address":"127.0.0.1","port":%d}]},"inbounds":[{"tag":"in_proxy","protocol":"tun","settings":{"name":"utun-dns6-fixture","MTU":1280}}],"outbounds":[{"tag":"proxy","protocol":"blackhole"},{"tag":"kindly-dns","protocol":"dns"},{"tag":"dns-wire","protocol":"freedom"}],"routing":{"rules":[{"type":"field","inboundTag":["in_proxy"],"port":"53","outboundTag":"kindly-dns"},{"type":"field","inboundTag":["kindly-dns-query"],"outboundTag":"dns-wire"},{"type":"field","ip":["::/0"],"outboundTag":"proxy"}]}}`, upstream.LocalAddr().(*net.UDPAddr).Port)
	app := ipv6FallbackCore(t, config)
	query := []byte{0x61, 0x72, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	udp := append(make([]byte, 8), query...)
	binary.BigEndian.PutUint16(udp[:2], 40204)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	ipv6FallbackWrite(t, app, 17, udp, 6)
	packet := ipv6FallbackRead(t, app)
	if len(packet) < 60 || packet[0]>>4 != 6 || packet[6] != 17 || packet[48] != 0x61 || packet[49] != 0x72 || binary.BigEndian.Uint16(packet[54:56]) != 1 {
		t.Fatalf("Intercepted IPv6 DNS must still answer A queries: %x", packet)
	}
	t.Log("IPv6 DNS control channel: A answer preserved while application IPv6 is disabled")
}

func ipv6FallbackWrite(t *testing.T, file *os.File, protocol byte, payload []byte, checksumOffset int) {
	t.Helper()
	source := net.ParseIP("fdfe:dcba:9876::2").To16()
	target := net.ParseIP("2001:db8:1::10").To16()
	pseudo := append(append([]byte{}, source...), target...)
	pseudo = binary.BigEndian.AppendUint32(pseudo, uint32(len(payload)))
	pseudo = append(pseudo, 0, 0, 0, protocol)
	binary.BigEndian.PutUint16(payload[checksumOffset:checksumOffset+2], tunTestChecksum(append(pseudo, payload...)))
	frame := make([]byte, 44+len(payload))
	frame[3], frame[4], frame[10], frame[11] = unix.AF_INET6, 0x60, protocol, 64
	binary.BigEndian.PutUint16(frame[8:10], uint16(len(payload)))
	copy(frame[12:28], source)
	copy(frame[28:44], target)
	copy(frame[44:], payload)
	if _, err := file.Write(frame); err != nil {
		t.Fatal(err)
	}
}

func ipv6FallbackRead(t *testing.T, file *os.File) []byte {
	t.Helper()
	var prefix [4]byte
	if _, err := io.ReadFull(file, prefix[:]); err != nil {
		t.Fatal("packet response:", err)
	}
	headerLength := 20
	if prefix[3] == unix.AF_INET6 {
		headerLength = 40
	} else if prefix[3] != unix.AF_INET {
		t.Fatalf("unknown packet family %x", prefix)
	}
	header := make([]byte, headerLength)
	if _, err := io.ReadFull(file, header); err != nil {
		t.Fatal(err)
	}
	length := int(binary.BigEndian.Uint16(header[2:4]))
	if headerLength == 40 {
		length = headerLength + int(binary.BigEndian.Uint16(header[4:6]))
	}
	if length < headerLength {
		t.Fatal("short IP packet")
	}
	packet := make([]byte, length)
	copy(packet, header)
	if _, err := io.ReadFull(file, packet[headerLength:]); err != nil {
		t.Fatal(err)
	}
	return packet
}
