//go:build darwin

package libXray

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/platform"
	"golang.org/x/sys/unix"
)

// Exercise the actual NetworkExtension socket framing and gVisor TCP/UDP
// paths. A dokodemo health probe alone never exercises either of these paths.
// All destinations are local fixtures; no external server or iPad is needed.
func TestPacketTunnelTransfersDNSAndBulkTCP(t *testing.T) {
	body := bytes.Repeat([]byte("packet-tunnel-data"), 65536)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	}))
	defer server.Close()
	_, targetPort, _ := net.SplitHostPort(server.Listener.Addr().String())
	dns, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := dns.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			reply := append([]byte(nil), buf[:n]...)
			reply[2], reply[3], reply[6], reply[7] = 0x81, 0x80, 0, 1
			reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 7)
			_, _ = dns.WriteTo(reply, addr)
		}
	}()
	dnsPort := dns.LocalAddr().(*net.UDPAddr).Port
	for _, preset := range []struct {
		name                     string
		memory, buffer, tcp, udp int32
	}{
		{"recent-restricted", 16, 64, 128, 64}, {"original-mobile", 30, 1024, 512, 256}, {"current-mobile", 24, 1024, 512, 256},
	} {
		t.Run(preset.name, func(t *testing.T) {
			fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
			if err != nil {
				t.Fatal(err)
			}
			app := os.NewFile(uintptr(fds[1]), "test-packet-flow")
			defer app.Close()
			defer unix.Close(fds[0])
			t.Setenv(platform.TunFdKey, strconv.Itoa(fds[0]))
			SetMemoryLimitMB(int64(preset.memory))
			SetTCPBufMaxKB(preset.buffer)
			SetTCPMaxInFlight(preset.tcp)
			SetMaxUDPConns(preset.udp)
			SetIPv6Enabled(false)
			defer SetIPv6Enabled(true)
			config := fmt.Sprintf(`{
"log":{"loglevel":"warning"},
"dns":{"queryStrategy":"UseIPv4","tag":"kindly-dns-query","servers":[{"address":"127.0.0.1","port":%d}]},
"inbounds":[{"tag":"in_proxy","protocol":"tun","settings":{"name":"utun-test","MTU":1280}}],
"outbounds":[{"tag":"proxy","protocol":"freedom","settings":{"redirect":"127.0.0.1:%s"}},{"tag":"kindly-dns","protocol":"dns"},{"tag":"dns-wire","protocol":"freedom"}],
"routing":{"rules":[{"type":"field","inboundTag":["in_proxy"],"port":"53","outboundTag":"kindly-dns"},{"type":"field","inboundTag":["kindly-dns-query"],"outboundTag":"dns-wire"},{"type":"field","network":"tcp,udp","outboundTag":"proxy"}]}
}`, dnsPort, targetPort)
			file := filepath.Join(t.TempDir(), "tun.json")
			if err := os.WriteFile(file, []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			request, _ := json.Marshal(runXrayRequest{ConfigPath: file})
			raw, err := base64.StdEncoding.DecodeString(RunXray(base64.StdEncoding.EncodeToString(request)))
			if err != nil {
				t.Fatal(err)
			}
			var result callResponse
			if err := json.Unmarshal(raw, &result); err != nil || !result.Success {
				t.Fatalf("core start: %s", raw)
			}
			defer func() { _ = unix.Shutdown(fds[1], unix.SHUT_RDWR); StopXray() }()
			// os.NewFile on this blocking socket does not provide deadlines. A
			// watchdog closes it so a broken pump fails promptly instead of hanging.
			timer := time.AfterFunc(20*time.Second, func() { _ = unix.Shutdown(fds[1], unix.SHUT_RDWR) })
			defer timer.Stop()
			query := []byte{0x61, 0x72, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
			udp := make([]byte, 8+len(query))
			binary.BigEndian.PutUint16(udp[0:2], 40300)
			binary.BigEndian.PutUint16(udp[2:4], 53)
			binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
			copy(udp[8:], query)
			tunTestWrite(t, app, 17, udp)
			for {
				packet := tunTestRead(t, app)
				if packet[9] != 17 {
					continue
				}
				offset := int(packet[0]&15)*4 + 8
				if len(packet) < offset+12 {
					t.Fatal("short DNS response")
				}
				d := packet[offset:]
				if d[0] != 0x61 || d[1] != 0x72 || d[3]&15 != 0 || binary.BigEndian.Uint16(d[6:8]) != 1 {
					t.Fatalf("invalid DNS reply: %x", d)
				}
				break
			}
			tunTestTCPWrite(t, app, 1, 0, 2, nil)
			var expected uint32
			for {
				p := tunTestRead(t, app)
				if p[9] != 6 {
					continue
				}
				tcp := p[int(p[0]&15)*4:]
				if tcp[13]&0x12 == 0x12 {
					expected = binary.BigEndian.Uint32(tcp[4:8]) + 1
					break
				}
				if tcp[13]&4 != 0 {
					t.Fatal("TUN reset TCP handshake")
				}
			}
			tunTestTCPWrite(t, app, 2, expected, 0x10, nil)
			get := []byte("GET /bulk HTTP/1.1\r\nHost: bulk.test\r\nConnection: close\r\n\r\n")
			clientSeq := uint32(2 + len(get))
			tunTestTCPWrite(t, app, 2, expected, 0x18, get)
			var received bytes.Buffer
			pending := map[uint32][]byte{}
			for {
				p := tunTestRead(t, app)
				if p[9] != 6 {
					continue
				}
				tcp := p[int(p[0]&15)*4:]
				if tcp[13]&4 != 0 {
					t.Fatal("TUN reset bulk transfer")
				}
				seq := binary.BigEndian.Uint32(tcp[4:8])
				payload := tcp[int(tcp[12]>>4)*4:]
				if len(payload) > 0 && int32(seq-expected) >= 0 {
					pending[seq] = append([]byte(nil), payload...)
				}
				for {
					data, ok := pending[expected]
					if !ok {
						break
					}
					received.Write(data)
					delete(pending, expected)
					expected += uint32(len(data))
				}
				if len(payload) > 0 {
					tunTestTCPWrite(t, app, clientSeq, expected, 0x10, nil)
				}
				if tcp[13]&1 != 0 && seq+uint32(len(payload)) == expected {
					tunTestTCPWrite(t, app, clientSeq, expected+1, 0x10, nil)
					break
				}
			}
			response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(received.Bytes())), nil)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || !bytes.Equal(body, actual) {
				t.Fatalf("bulk data corrupted/truncated: got %d, expected %d, error %v", len(actual), len(body), err)
			}
			t.Logf("TUN DNS reply and %d bytes of TCP payload verified", len(actual))
			// Native UDP sessions remain alive after the first DNS reply. The
			// reduced 64-session cap silently discarded every new client once
			// those slots filled, while loopback health requests still worked.
			const queries = 80
			for index := 0; index < queries; index++ {
				copy(udp[8:], query)
				binary.BigEndian.PutUint16(udp[0:2], uint16(42000+index))
				binary.BigEndian.PutUint16(udp[8:10], uint16(0x6200+index))
				tunTestWrite(t, app, 17, udp)
			}
			deadline := time.AfterFunc(2*time.Second, func() { _ = unix.Shutdown(fds[1], unix.SHUT_RDWR) })
			defer deadline.Stop()
			replies := map[uint16]bool{}
			for len(replies) < queries {
				packet, err := tunTestReadPacket(app)
				if err != nil {
					break
				}
				if packet[9] != 17 {
					continue
				}
				offset := int(packet[0]&15)*4 + 8
				if len(packet) < offset+12 {
					t.Fatal("truncated DNS stress reply")
				}
				id := binary.BigEndian.Uint16(packet[offset : offset+2])
				if id >= 0x6200 && id < 0x6200+queries {
					replies[id] = true
				}
			}
			deadline.Stop()
			t.Logf("TUN DNS stress: %d/%d answered with UDP limit %d", len(replies), queries, preset.udp)
			if preset.udp == 64 && len(replies) >= queries {
				t.Fatal("restricted preset did not reproduce UDP exhaustion")
			}
			if preset.udp >= queries && len(replies) != queries {
				t.Fatal("original mobile preset lost DNS clients")
			}
		})
	}
}

func tunTestRead(t *testing.T, file *os.File) []byte {
	t.Helper()
	packet, err := tunTestReadPacket(file)
	if err != nil {
		t.Fatal("packet pump did not reply:", err)
	}
	return packet
}

func tunTestReadPacket(file *os.File) ([]byte, error) {
	h := make([]byte, 24)
	if _, err := io.ReadFull(file, h); err != nil {
		return nil, err
	}
	if h[3] != unix.AF_INET {
		return nil, fmt.Errorf("unexpected packet family: %x", h[:4])
	}
	length := int(binary.BigEndian.Uint16(h[6:8]))
	if length < 20 {
		return nil, fmt.Errorf("invalid packet length: %d", length)
	}
	p := make([]byte, length)
	copy(p, h[4:])
	if _, err := io.ReadFull(file, p[20:]); err != nil {
		return nil, err
	}
	return p, nil
}

func tunTestWrite(t *testing.T, file *os.File, protocol byte, payload []byte) {
	t.Helper()
	p := make([]byte, 24+len(payload))
	p[3] = unix.AF_INET
	p[4] = 0x45
	binary.BigEndian.PutUint16(p[6:8], uint16(20+len(payload)))
	p[12] = 64
	p[13] = protocol
	copy(p[16:20], []byte{198, 18, 0, 2})
	copy(p[20:24], []byte{203, 0, 113, 10})
	binary.BigEndian.PutUint16(p[14:16], tunTestChecksum(p[4:24]))
	copy(p[24:], payload)
	if _, err := file.Write(p); err != nil {
		t.Fatal(err)
	}
}

func tunTestTCPWrite(t *testing.T, file *os.File, seq, ack uint32, flags byte, payload []byte) {
	tunTestTCPWritePort(t, file, 40200, seq, ack, flags, payload)
}
func tunTestTCPWritePort(t *testing.T, file *os.File, port uint16, seq, ack uint32, flags byte, payload []byte) {
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], port)
	binary.BigEndian.PutUint16(tcp[2:4], 80)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], payload)
	pseudo := []byte{198, 18, 0, 2, 203, 0, 113, 10, 0, 6, byte(len(tcp) >> 8), byte(len(tcp))}
	pseudo = append(pseudo, tcp...)
	binary.BigEndian.PutUint16(tcp[16:18], tunTestChecksum(pseudo))
	tunTestWrite(t, file, 6, tcp)
}

func tunTestChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) > 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}

// Real framed IP -> Xray TUN -> SOCKS -> encrypted AWG -> server netstack.
// Socket loss must recover in place: the VPN/core and TCP router stay alive.
func TestAmneziaPacketTunnelSocketRefresh(t *testing.T) {
	privateA, publicA := amneziaTestKey(t)
	privateB, publicB := amneziaTestKey(t)
	cfg := func(private, public, address string) amneziaConfig {
		return amneziaConfig{Addresses: []string{address}, MTU: 1280, UAPI: "private_key=" + private + "\nreplace_peers=true\npublic_key=" + public + "\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=1\n"}
	}
	server, err := newAmneziaProxy(cfg(privateA, publicB, "203.0.113.10"), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	info, err := server.device.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	var port string
	for _, line := range strings.Split(info, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			port = strings.TrimPrefix(line, "listen_port=")
		}
	}
	if port == "" {
		t.Fatal("missing fixture port")
	}
	listener, err := server.network.ListenTCPAddrPort(netip.MustParseAddrPort("203.0.113.10:80"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	body := bytes.Repeat([]byte("encrypted-packet-flow"), 32768)
	httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Write(body)
	})}
	go httpServer.Serve(listener)
	defer httpServer.Close()
	udp, err := server.network.ListenUDP(&net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 53})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, source, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			udp.WriteTo(buf[:n], source)
		}
	}()
	clientCfg := cfg(privateB, publicA, "203.0.113.11")
	clientCfg.UAPI += "endpoint=127.0.0.1:" + port + "\n"
	// The installed Mac app may own 9004. Use an ephemeral fixture listener;
	// never stop or interfere with the host's VPN to free its production port.
	fixtureClient, err := newAmneziaProxy(clientCfg, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer fixtureClient.Close()
	fixturePort := fixtureClient.listener.Addr().(*net.TCPAddr).Port
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	app := os.NewFile(uintptr(fds[1]), "awg-test-packet-flow")
	defer app.Close()
	defer unix.Close(fds[0])
	t.Setenv(platform.TunFdKey, strconv.Itoa(fds[0]))
	// Race instrumentation adds substantial allocation/CPU overhead to two
	// packet stacks. The ordinary fixture retains the production 24 MB ceiling.
	if os.Getenv("TNDTUN_NATIVE_RACE") == "1" {
		SetMemoryLimitMB(128)
	} else {
		SetMemoryLimitMB(24)
	}
	SetTCPBufMaxKB(1024)
	SetTCPMaxInFlight(512)
	SetMaxUDPConns(256)
	SetIPv6Enabled(false)
	defer SetIPv6Enabled(true)
	config := map[string]any{

		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  []any{map[string]any{"tag": "in_proxy", "protocol": "tun", "settings": map[string]any{"name": "utun-awg-test", "MTU": 1280}}},
		"outbounds": []any{map[string]any{"tag": "proxy", "protocol": "socks", "settings": map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": fixturePort}}}}},
	}
	data, _ := json.Marshal(config)
	file := filepath.Join(t.TempDir(), "awg-tun.json")
	if err = os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	request, _ := json.Marshal(runXrayRequest{ConfigPath: file})
	raw, err := base64.StdEncoding.DecodeString(RunXray(base64.StdEncoding.EncodeToString(request)))
	if err != nil {
		t.Fatal(err)
	}
	var result callResponse
	if err = json.Unmarshal(raw, &result); err != nil || !result.Success {
		t.Fatalf("core failed: %s", raw)
	}
	defer func() { unix.Shutdown(fds[1], unix.SHUT_RDWR); StopXray() }()
	timer := time.AfterFunc(45*time.Second, func() { unix.Shutdown(fds[1], unix.SHUT_RDWR) })
	defer timer.Stop()
	xrayState.Lock()
	xrayState.amnezia = fixtureClient
	client, core := xrayState.amnezia, xrayState.server
	xrayState.Unlock()
	if client == nil {
		t.Fatal("Amnezia not running")
	}
	for cycle := 0; cycle < 2; cycle++ {
		if cycle == 1 {
			if err := client.device.BindClose(); err != nil {
				t.Fatal(err)
			}
			// Direct inner-stack traffic now has no UDP receive sockets. Prove the
			// injected fault rather than silently testing an already healthy tunnel.
			probe, err := client.network.DialContext(context.Background(), "udp", "203.0.113.10:53")
			if err != nil {
				t.Fatal(err)
			}
			probe.SetDeadline(time.Now().Add(150 * time.Millisecond))
			probe.Write([]byte("closed-bind"))
			buf := make([]byte, 64)
			_, err = probe.Read(buf)
			probe.Close()
			if err == nil {
				t.Fatal("socket fault did not interrupt encrypted traffic")
			}
			for i := 0; i < 32; i++ {
				if !AmneziaRefreshSockets() {
					t.Fatal("refresh rejected")
				}
			}
		}
		payload := []byte(fmt.Sprintf("encrypted-dns-cycle-%d", cycle))
		datagram := make([]byte, 8+len(payload))
		binary.BigEndian.PutUint16(datagram[0:2], uint16(40500+cycle))
		binary.BigEndian.PutUint16(datagram[2:4], 53)
		binary.BigEndian.PutUint16(datagram[4:6], uint16(len(datagram)))
		copy(datagram[8:], payload)
		tunTestWrite(t, app, 17, datagram)
		for {
			packet := tunTestRead(t, app)
			if packet[9] != 17 {
				continue
			}
			offset := int(packet[0]&15) * 4
			if binary.BigEndian.Uint16(packet[offset+2:offset+4]) != uint16(40500+cycle) {
				continue
			}
			if !bytes.Equal(packet[offset+8:], payload) {
				t.Fatal("encrypted UDP corrupted")
			}
			break
		}
		tcpPort := uint16(40600 + cycle)
		write := func(seq, ack uint32, flags byte, payload []byte) {
			tunTestTCPWritePort(t, app, tcpPort, seq, ack, flags, payload)
		}
		read := func() []byte {
			for {
				packet := tunTestRead(t, app)
				if packet[9] != 6 {
					continue
				}
				tcp := packet[int(packet[0]&15)*4:]
				if binary.BigEndian.Uint16(tcp[2:4]) == tcpPort {
					return tcp
				}
			}
		}
		write(1, 0, 2, nil)
		var expected uint32
		for {
			tcp := read()
			if tcp[13]&4 != 0 {
				t.Fatal("handshake reset")
			}
			if tcp[13]&0x12 == 0x12 {
				expected = binary.BigEndian.Uint32(tcp[4:8]) + 1
				break
			}
		}
		write(2, expected, 0x10, nil)
		get := []byte("GET / HTTP/1.1\r\nHost: awg.test\r\nConnection: close\r\n\r\n")
		clientSeq := uint32(2 + len(get))
		write(2, expected, 0x18, get)
		var received bytes.Buffer
		pending := map[uint32][]byte{}
		for {
			tcp := read()
			if tcp[13]&4 != 0 {
				t.Fatal("encrypted TCP reset")
			}
			seq := binary.BigEndian.Uint32(tcp[4:8])
			payload := tcp[int(tcp[12]>>4)*4:]
			if len(payload) > 0 && int32(seq-expected) >= 0 {
				pending[seq] = append([]byte(nil), payload...)
			}
			for {
				data, ok := pending[expected]
				if !ok {
					break
				}
				received.Write(data)
				delete(pending, expected)
				expected += uint32(len(data))
			}
			if len(payload) > 0 {
				write(clientSeq, expected, 0x10, nil)
			}
			if tcp[13]&1 != 0 && seq+uint32(len(payload)) == expected {
				write(clientSeq, expected+1, 0x11, nil)
				break
			}
		}
		response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(received.Bytes())), nil)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || !bytes.Equal(actual, body) {
			t.Fatalf("encrypted bulk corrupted: %d/%d, %v", len(actual), len(body), err)
		}
		xrayState.Lock()
		same := xrayState.amnezia == client && xrayState.server == core
		xrayState.Unlock()
		if !same {
			t.Fatal("core or device replaced")
		}
		t.Logf("cycle %d: framed TUN encrypted UDP and %d TCP bytes; same device/core", cycle, len(actual))
	}
	// A queued network event cannot reopen a stopped transport.
	client.networkChanged()
	StopXray()
	if AmneziaRefreshSockets() || client.networkChanged() {
		t.Fatal("stopped device accepted a refresh")
	}
}
