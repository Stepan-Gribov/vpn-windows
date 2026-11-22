package libXray

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// Recovery must restart the native core cleanly and force health traffic ahead
// of normal bypass rules. All traffic stays on loopback; no production access.
func TestHealthProbeRouteSurvivesCoreRestart(t *testing.T) {
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer endpoint.Close()
	_, targetPort, err := net.SplitHostPort(endpoint.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(targetPort)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	probePort := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	config := fmt.Sprintf(`{
        "log":{"loglevel":"none"},
        "inbounds":[{"tag":"kindly-health","listen":"127.0.0.1","port":%d,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1","port":%d,"network":"tcp"}}],
        "outbounds":[{"tag":"direct","protocol":"blackhole"},{"tag":"proxy","protocol":"freedom"}],
        "routing":{"rules":[{"type":"field","inboundTag":["kindly-health"],"outboundTag":"proxy"},{"type":"field","network":"tcp,udp","outboundTag":"direct"}]}
    }`, probePort, port)
	path := filepath.Join(t.TempDir(), "probe.json")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	request, _ := json.Marshal(runXrayRequest{ConfigPath: path})
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	defer client.CloseIdleConnections()
	defer StopXray()
	for attempt := 0; attempt < 3; attempt++ {
		raw, err := base64.StdEncoding.DecodeString(RunXray(base64.StdEncoding.EncodeToString(request)))
		if err != nil {
			t.Fatal(err)
		}
		var response callResponse
		if err := json.Unmarshal(raw, &response); err != nil {
			t.Fatal(err)
		}
		if !response.Success {
			t.Fatalf("restart %d failed: %s", attempt, response.Error)
		}
		result, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/health", probePort))
		if err != nil {
			t.Fatal(err)
		}
		_ = result.Body.Close()
		if result.StatusCode != http.StatusNoContent {
			t.Fatalf("HTTP %d", result.StatusCode)
		}
		raw, err = base64.StdEncoding.DecodeString(StopXray())
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(raw, &response); err != nil || !response.Success {
			t.Fatalf("stop failed: %s", raw)
		}
	}
}
