package libXray

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// Exercise real sniffing with a literal packet destination, as a browser's TUN
// connection does. The earlier SOCKS-only fixture had neither TLS nor sniffing.
func TestSplitTunnelSniffedTLSAndIPv6(t *testing.T) {
	directory := os.Getenv("KINDLYVPN_CONFIG_FIXTURES")
	if directory == "" {
		t.Skip("Run Scripts/test-split-routing.sh")
	}
	endpoint := func(marker string) *httptest.Server {
		return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			for _, part := range []string{"data: " + marker + "\n\n", "data: done\n\n"} {
				_, _ = io.WriteString(w, part)
				w.(http.Flusher).Flush()
			}
		}))
	}
	direct, tunneled := endpoint("direct"), endpoint("proxy")
	defer direct.Close()
	defer tunneled.Close()
	for _, mode := range []string{"disabled", "bypassSelected", "tunnelSelected"} {
		t.Run(mode, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(directory, mode+"-ipv6.json"))
			if err != nil {
				t.Fatal(err)
			}
			var config map[string]any
			if err = json.Unmarshal(data, &config); err != nil {
				t.Fatal(err)
			}
			inbound := config["inbounds"].([]any)[0].(map[string]any)
			sniffing := inbound["sniffing"].(map[string]any)
			if sniffing["enabled"] != true || (mode != "disabled" && sniffing["routeOnly"] != true) {
				t.Fatal("fixture must carry the real extension's TLS route-only sniffing")
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			_ = listener.Close()
			config["inbounds"] = []any{map[string]any{
				"tag": "in_proxy", "protocol": "socks", "listen": "127.0.0.1", "port": port,
				"settings": map[string]any{"auth": "noauth"}, "sniffing": sniffing,
			}}
			freedom := func(tag, address string) map[string]any {
				return map[string]any{"tag": tag, "protocol": "freedom", "settings": map[string]any{"redirect": address}}
			}
			config["outbounds"] = []any{
				freedom("direct", direct.Listener.Addr().String()), freedom("proxy", tunneled.Listener.Addr().String()),
				map[string]any{"tag": "block", "protocol": "blackhole"}, map[string]any{"tag": "kindly-dns", "protocol": "dns"},
			}
			path := filepath.Join(t.TempDir(), "tls-routing.json")
			data, err = json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			request, _ := json.Marshal(runXrayRequest{ConfigPath: path})
			raw, err := base64.StdEncoding.DecodeString(RunXray(base64.StdEncoding.EncodeToString(request)))
			if err != nil {
				t.Fatal(err)
			}
			var result callResponse
			if err = json.Unmarshal(raw, &result); err != nil || !result.Success {
				t.Fatalf("start: %s", raw)
			}
			defer StopXray()
			dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), nil, &net.Dialer{Timeout: 3 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range []struct {
				ip, sni  string
				selected bool
			}{
				{"203.0.113.10", "cdn.test", true},
				{"203.0.113.20", "selected.test", false},
				{"203.0.113.20", "manual.test", true},
				{"2001:db8:1::10", "cdn.test", true},
				{"2001:db8:2::20", "selected.test", false},
				{"2001:db8:2::20", "manual.test", true},
				{"203.0.113.10", "", true},
			} {
				expected := "proxy"
				if mode == "bypassSelected" && target.selected || mode == "tunnelSelected" && !target.selected {
					expected = "direct"
				}
				transport := &http.Transport{
					DisableKeepAlives: true,
					// Only the local generated test certificate is accepted here.
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: target.sni},
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return dialer.(proxy.ContextDialer).DialContext(ctx, network, address)
					},
				}
				client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
				response, err := client.Get("https://" + net.JoinHostPort(target.ip, "443") + "/")
				if err != nil {
					transport.CloseIdleConnections()
					t.Fatalf("%s SNI %q: %v", target.ip, target.sni, err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				transport.CloseIdleConnections()
				if err != nil || !strings.Contains(string(body), "data: "+expected+"\n\n") || !strings.Contains(string(body), "data: done\n\n") {
					t.Fatalf("%s SNI %q streamed %q; want %s (%v)", target.ip, target.sni, body, expected, err)
				}
				t.Logf("%s SNI %q -> %s; stream complete", target.ip, target.sni, expected)
			}
		})
	}
}
