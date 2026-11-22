package libXray

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/proxy"
)

func amneziaTestKey(t *testing.T) (string, string) {
	t.Helper()
	private := make([]byte, 32)
	if _, err := rand.Read(private); err != nil {
		t.Fatal(err)
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(private), hex.EncodeToString(public)
}
func amneziaHTTPClient(t *testing.T, p *amneziaProxy) *http.Client {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", p.listener.Addr().String(), nil, &net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, DialContext: dialer.(proxy.ContextDialer).DialContext}}
	t.Cleanup(client.CloseIdleConnections)
	return client
}
func TestAmneziaWG3EncryptedTCPUDPAndRestart(t *testing.T) {
	privateA, publicA := amneziaTestKey(t)
	privateB, publicB := amneziaTestKey(t)
	protection := strings.Repeat("ab", 32)
	parameters := "jc=3\njmin=30\njmax=60\ns1=17\ns2=19\ns3=13\ns4=15\nh1=150-200\nh2=250-300\nh3=350-400\nh4=450-500\nheader_protection_key=" + protection + "\nrandom_trailers=true\ndisable_cookies=true\n"
	cfg := func(private, public, address string) amneziaConfig {
		return amneziaConfig{Addresses: []string{address}, DNS: []string{"10.80.0.1"}, MTU: 1280, UAPI: "private_key=" + private + "\n" + parameters + "replace_peers=true\npublic_key=" + public + "\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=1\n"}
	}
	server, err := newAmneziaProxy(cfg(privateA, publicB, "10.80.0.1"), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	info, err := server.device.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	port := ""
	for _, line := range strings.Split(info, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			port = strings.TrimPrefix(line, "listen_port=")
		}
	}
	if port == "" {
		t.Fatal("server UDP port missing")
	}
	listener, err := server.network.ListenTCPAddrPort(netip.MustParseAddrPort("10.80.0.1:80"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "encrypted-awg3") })}
	go httpServer.Serve(listener)
	defer httpServer.Close()
	udp, err := server.network.ListenUDP(&net.UDPAddr{IP: net.ParseIP("10.80.0.1"), Port: 53})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, source, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			udp.WriteTo(buffer[:n], source)
		}
	}()
	for attempt := 0; attempt < 2; attempt++ {
		clientCfg := cfg(privateB, publicA, "10.80.0.2")
		clientCfg.UAPI += "endpoint=127.0.0.1:" + port + "\n"
		client, err := newAmneziaProxy(clientCfg, "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer client.Close()
			response, err := amneziaHTTPClient(t, client).Get("http://10.80.0.1/")
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if string(body) != "encrypted-awg3" {
				t.Fatal("wrong tunneled response")
			}
			control, err := net.DialTimeout("tcp", client.listener.Addr().String(), 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer control.Close()
			control.SetDeadline(time.Now().Add(5 * time.Second))
			control.Write([]byte{5, 1, 0})
			var greeting [2]byte
			if _, err := io.ReadFull(control, greeting[:]); err != nil {
				t.Fatal(err)
			}
			control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
			var reply [4]byte
			if _, err := io.ReadFull(control, reply[:]); err != nil || reply[1] != 0 {
				t.Fatal("UDP association failed")
			}
			target, err := readAmneziaAddress(control, reply[3])
			if err != nil {
				t.Fatal(err)
			}
			local, err := net.DialTimeout("udp", target, 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer local.Close()
			local.SetDeadline(time.Now().Add(5 * time.Second))
			packet := append([]byte{0, 0, 0, 1, 10, 80, 0, 1, 0, 53}, []byte("udp-dns-fixture")...)
			local.Write(packet)
			buffer := make([]byte, 4096)
			n, err := local.Read(buffer)
			if err != nil {
				t.Fatal(err)
			}
			if string(buffer[10:n]) != "udp-dns-fixture" {
				t.Fatal("UDP reply corrupted")
			}
			t.Logf("cycle %d: AWG3 TCP and UDP transferred", attempt+1)
		}()
	}
}

func TestAmneziaRejectsUnsafeRuntimeSettings(t *testing.T) {
	config := amneziaConfig{Addresses: []string{"10.0.0.2"}, DNS: []string{"1.1.1.1"}, MTU: 1280, UAPI: "private_key=bad\npost_up=command\n"}
	if err := config.validate(); err == nil {
		t.Fatal("unknown setting accepted")
	}
	config.UAPI = "private_key=bad\n"
	if p, err := newAmneziaProxy(config, "127.0.0.1:0"); err == nil {
		p.Close()
		t.Fatal("invalid key accepted")
	}
}
func TestAmneziaLiveConnection(t *testing.T) {
	file := os.Getenv("TNDTUN_AMNEZIA_LIVE_CONFIG")
	if file == "" {
		t.Skip("requires a local authorized test configuration")
	}
	bytes, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var config amneziaConfig
	if err = json.Unmarshal(bytes, &config); err != nil {
		t.Fatal("invalid test payload")
	}
	p, err := newAmneziaProxy(config, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	client := amneziaHTTPClient(t, p)
	for _, url := range []string{"https://www.google.com/generate_204", "https://www.youtube.com/"} {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		request, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		response, err := client.Do(request)
		cancel()
		if err != nil {
			t.Fatal("tunneled HTTPS failed:", err)
		}
		response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 400 {
			t.Fatal("unexpected response", response.StatusCode)
		}
		t.Log(fmt.Sprintf("tunneled HTTPS status: %d", response.StatusCode))
	}
}

// The receiver deliberately waits for EOF before replying. Closing the whole
// tunneled socket on the client's FIN loses a valid response.
func TestAmneziaTCPHalfClosePreservesResponse(t *testing.T) {
	privateA, publicA := amneziaTestKey(t)
	privateB, publicB := amneziaTestKey(t)
	config := func(private, public, address string) amneziaConfig {
		return amneziaConfig{Addresses: []string{address}, MTU: 1280, UAPI: "private_key=" + private + "\nreplace_peers=true\npublic_key=" + public + "\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=1\n"}
	}
	server, err := newAmneziaProxy(config(privateA, publicB, "10.81.0.1"), "127.0.0.1:0")
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
		t.Fatal("missing fixture UDP port")
	}
	listener, err := server.network.ListenTCPAddrPort(netip.MustParseAddrPort("10.81.0.1:8080"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	payload := bytes.Repeat([]byte("encrypted-half-close-response"), 32768)
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(8 * time.Second))
		request, err := io.ReadAll(conn)
		if err == nil && string(request) != "request" {
			err = fmt.Errorf("unexpected request")
		}
		if err == nil {
			_, err = conn.Write(payload)
		}
		serverDone <- err
	}()
	cfg := config(privateB, publicA, "10.81.0.2")
	cfg.UAPI += "endpoint=127.0.0.1:" + port + "\n"
	client, err := newAmneziaProxy(cfg, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	dialer, err := proxy.SOCKS5("tcp", client.listener.Addr().String(), nil, &net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.Dial("tcp", "10.81.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err = io.WriteString(conn, "request"); err != nil {
		t.Fatal(err)
	}
	if err = conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatalf("response truncated after FIN: got %d of %d bytes", len(response), len(payload))
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}
