package libXray

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Uses real Wintun and gVisor with two isolated /32 routes. Never installs
// default routes or system DNS and does not require a VPN/server credential.
func TestWindowsSystemTunnelTCPUDPAndCleanup(t *testing.T) {
	if os.Getenv("TNDTUN_SYSTEM_TEST") != "1" {
		t.Skip("explicit isolated Wintun fixture required")
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "tndtun-real-wintun-fixture") }))
	defer target.Close()
	udp, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	ds := &dns.Server{PacketConn: udp, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		t.Log("UDP fixture received DNS request")
		m := new(dns.Msg)
		m.SetReply(r)
		rr, _ := dns.NewRR(r.Question[0].Name + " 60 IN A 203.0.113.19")
		m.Answer = []dns.RR{rr}
		w.WriteMsg(m)
	})}
	go ds.ActivateAndServe()
	defer ds.Shutdown()
	cfg := map[string]any{
		"log":       map[string]any{"loglevel": "debug"},
		"inbounds":  []any{map[string]any{"tag": "in_proxy", "protocol": "tun", "settings": map[string]any{"name": "TnDtunFixture", "mtu": 1280, "gateway": []string{"198.18.100.1/30"}, "autoSystemRoutingTable": []string{"198.19.0.1/32", "198.19.0.2/32"}}}},
		"outbounds": []any{map[string]any{"tag": "tcp", "protocol": "freedom", "settings": map[string]any{"redirect": target.Listener.Addr().String()}}, map[string]any{"tag": "dns", "protocol": "freedom", "settings": map[string]any{"redirect": udp.LocalAddr().String()}}},
		"routing":   map[string]any{"rules": []any{map[string]any{"type": "field", "port": "53", "outboundTag": "dns"}}},
		"stats":     map[string]any{}, "policy": map[string]any{"system": map[string]any{"statsInboundUplink": true, "statsInboundDownlink": true}},
	}
	raw, _ := json.Marshal(cfg)
	defer StopXray()
	if e = DesktopStart(string(raw)); e != nil {
		t.Fatal(e)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(15 * time.Second)
	var body []byte
	for time.Now().Before(deadline) {
		r, err := client.Get("http://198.19.0.1:80/fixture")
		e = err
		if err == nil {
			body, e = io.ReadAll(r.Body)
			r.Body.Close()
			if e == nil {
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if e != nil || string(body) != "tndtun-real-wintun-fixture" {
		t.Fatalf("real TUN TCP failed: %v", e)
	}
	q := new(dns.Msg)
	q.SetQuestion("wintun-fixture.example.", dns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	answer, _, e := (&dns.Client{Net: "udp", Timeout: 5 * time.Second}).ExchangeContext(ctx, q, "198.19.0.2:53")
	if e != nil || answer == nil || len(answer.Answer) != 1 {
		t.Fatalf("real TUN UDP DNS failed: %v", e)
	}
	if answer.Answer[0].(*dns.A).A.String() != "203.0.113.19" {
		t.Fatal("wrong DNS response")
	}
	up, down := DesktopStats()
	if up == 0 || down == 0 {
		t.Fatalf("missing TUN traffic counters: %d/%d", up, down)
	}
	StopXray()
	for i := 0; i < 30; i++ {
		interfaces, _ := net.Interfaces()
		found := false
		for _, v := range interfaces {
			if v.Name == "TnDtunFixture" {
				found = true
			}
		}
		if !found {
			t.Log(fmt.Sprintf("real Wintun TCP/UDP passed; counters %d/%d; adapter removed", up, down))
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("fixture adapter remained after stop")
}
