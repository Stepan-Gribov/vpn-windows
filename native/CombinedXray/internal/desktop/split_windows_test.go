package desktop

import (
	"io"
	lib "kindlyvpn/native"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func TestWindowsSplitTunnelActualRoutes(t *testing.T) {
	if os.Getenv("TNDTUN_SYSTEM_TEST") != "1" {
		t.Skip("explicit isolated Wintun fixture required")
	}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "proxy") }))
	defer proxy.Close()
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "direct") }))
	defer direct.Close()
	for _, mode := range []string{"bypassSelected", "tunnelSelected"} {
		t.Run(mode, func(t *testing.T) {
			s := DefaultState().Settings
			s.Split = Split{Mode: mode, Bypass: []Entry{{Address: "198.19.1.1/32"}}, Tunnel: []Entry{{Address: "198.19.1.1/32"}}}
			config := func(full bool) string {
				cfg, e := BuildConfig(Builtin(), s.effectiveRouting("turn", full), "auto", 12345, 0, true)
				if e != nil {
					t.Fatal(e)
				}
				in := cfg["inbounds"].([]any)[1].(map[string]any)
				in["settings"] = map[string]any{"name": "TnDtunSplitFixture", "mtu": 1280, "gateway": []string{"198.18.101.1/30"}, "autoSystemRoutingTable": []string{"198.19.1.1/32", "198.19.1.2/32"}}
				cfg["inbounds"] = []any{in}
				for _, out := range cfg["outbounds"].([]any) {
					m := out.(map[string]any)
					target := ""
					if m["tag"] == "proxy" {
						target = proxy.Listener.Addr().String()
					}
					if m["tag"] == "direct" {
						target = direct.Listener.Addr().String()
					}
					if target != "" {
						m["protocol"] = "freedom"
						m["settings"] = map[string]any{"redirect": target}
					}
				}
				return string(Pack(cfg))
			}
			defer lib.StopXray()
			if e := lib.DesktopStart(config(false)); e != nil {
				t.Fatal(e)
			}
			client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 5 * time.Second}
			defer client.CloseIdleConnections()
			check := func(full bool) {
				for _, ip := range []string{"198.19.1.1", "198.19.1.2"} {
					expected := "proxy"
					if !full && ((mode == "bypassSelected" && ip == "198.19.1.1") || (mode == "tunnelSelected" && ip == "198.19.1.2")) {
						expected = "direct"
					}
					r, e := client.Get("http://" + ip + "/split")
					if e != nil {
						t.Fatal(e)
					}
					b, e := io.ReadAll(r.Body)
					r.Body.Close()
					if e != nil || string(b) != expected {
						t.Fatalf("%s: got %s want %s (%v)", ip, b, expected, e)
					}
				}
			}
			check(false)
			if e := lib.DesktopReconfigure(config(true)); e != nil {
				t.Fatal(e)
			}
			check(true)
			if e := lib.DesktopReconfigure(config(false)); e != nil {
				t.Fatal(e)
			}
			check(false)
			iface, err := net.InterfaceByName("TnDtunSplitFixture")
			if err != nil {
				t.Fatal(err)
			}
			luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index))
			if err != nil {
				t.Fatal(err)
			}
			route := netip.MustParsePrefix("198.19.1.1/32")
			if _, err = luid.Route(route, netip.IPv4Unspecified()); err != nil {
				t.Fatal(err)
			}
			if err = lib.DesktopReleaseSystemRoutes("TnDtunSplitFixture"); err != nil {
				t.Fatal(err)
			}
			if _, err = luid.Route(route, netip.IPv4Unspecified()); err == nil {
				t.Fatal("fixture route remained captured")
			}
			if _, err = net.InterfaceByName("TnDtunSplitFixture"); err != nil {
				t.Fatal("release tore down adapter prematurely")
			}

			lib.StopXray()
			t.Log("real Wintun split → full tunnel → split; route released before adapter teardown")
		})
	}
}
