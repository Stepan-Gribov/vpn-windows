package libXray

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/xtls/xray-core/common/platform"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPhysicalDNSAnswersPacketsWhileProxyIsDown(t *testing.T) {
	var ifaceName, ip string
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		if !(strings.HasPrefix(iface.Name, "en") || strings.HasPrefix(iface.Name, "pdp_ip")) || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, _ := iface.Addrs()
		for _, address := range addresses {
			candidate, _, _ := net.ParseCIDR(address.String())
			if candidate.To4() != nil {
				ifaceName = iface.Name
				ip = candidate.String()
				break
			}
		}
		if ip != "" {
			break
		}
	}
	if ip == "" {
		t.Skip("No physical IPv4 interface for the bound DNS fixture")
	}
	upstream, err := net.ListenPacket("udp4", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, source, err := upstream.ReadFrom(buffer)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			reply := append([]byte(nil), buffer[:n]...)
			reply[2], reply[3], reply[6], reply[7] = 0x81, 0x80, 0, 1
			reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 7)
			upstream.WriteTo(reply, source)
		}
	}()
	resolvers, _ := json.Marshal([]string{upstream.LocalAddr().String()})
	port := KindlyPhysicalDNSStart(ifaceName, string(resolvers))
	if port <= 0 {
		t.Fatal("physical DNS start")
	}
	defer KindlyPhysicalDNSStop()
	if KindlyPhysicalDNSStart("utun-nonexistent", string(resolvers)) != 0 {
		t.Fatal("VPN interface accepted as physical")
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	app := os.NewFile(uintptr(fds[1]), "physical-dns-packet-flow")
	defer app.Close()
	defer unix.Close(fds[0])
	t.Setenv(platform.TunFdKey, strconv.Itoa(fds[0]))
	config := fmt.Sprintf(`{"log":{"loglevel":"warning"},"dns":{"queryStrategy":"UseIPv4","servers":[{"address":"tcp+local://127.0.0.1:%d"}]},"inbounds":[{"tag":"in_proxy","protocol":"tun","settings":{"name":"utun-fixture","MTU":1280}}],"outbounds":[{"tag":"proxy","protocol":"blackhole"},{"tag":"direct","protocol":"freedom"},{"tag":"kindly-dns","protocol":"dns"}],"routing":{"domainStrategy":"AsIs","rules":[{"type":"field","inboundTag":["in_proxy"],"port":"53","outboundTag":"kindly-dns"},{"type":"field","network":"tcp,udp","outboundTag":"proxy"}]}}`, port)
	file := filepath.Join(t.TempDir(), "physical-dns.json")
	if err := os.WriteFile(file, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	request, _ := json.Marshal(runXrayRequest{ConfigPath: file})
	raw, _ := base64.StdEncoding.DecodeString(RunXray(base64.StdEncoding.EncodeToString(request)))
	var result callResponse
	if json.Unmarshal(raw, &result) != nil || !result.Success {
		t.Fatalf("start core: %s", raw)
	}
	defer func() { unix.Shutdown(fds[1], unix.SHUT_RDWR); StopXray() }()
	timer := time.AfterFunc(10*time.Second, func() { unix.Shutdown(fds[1], unix.SHUT_RDWR) })
	defer timer.Stop()
	query := []byte{0x61, 0x72, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}
	udp := make([]byte, 8+len(query))
	binary.BigEndian.PutUint16(udp[0:2], 40400)
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
		dns := packet[offset:]
		if len(dns) < 12 {
			t.Fatal("short DNS reply")
		}
		if dns[0] != 0x61 || dns[1] != 0x72 || dns[3]&15 != 0 || binary.BigEndian.Uint16(dns[6:8]) != 1 {
			t.Fatalf("direct DNS failed: %x", dns)
		}
		break
	}
	t.Log("A real packet DNS request succeeded over physical bound DNS while the proxy outbound blackholed traffic")
}
