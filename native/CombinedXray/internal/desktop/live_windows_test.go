package desktop

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Administrator provisions a separate, expiring test account and revokes it
// after this run. Never reuse a production device or its Amnezia private key.
func TestWindowsLiveOwnSubscription(t *testing.T) {
	path := os.Getenv("TNDTUN_LIVE_ACTIVATION_FILE")
	if path == "" {
		t.Skip("isolated live account required")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		Code         string `json:"code"`
		Installation string `json:"installationID"`
	}
	if json.Unmarshal(b, &fixture) != nil || fixture.Code == "" {
		t.Fatal("invalid live fixture")
	}
	t.Setenv("TNDTUN_TEST_DATA", t.TempDir())
	c, e := NewController(io.Discard)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Stop()
	if fixture.Installation != "" {
		c.s.Installation = fixture.Installation
	}
	if e = c.Activate(fixture.Code, false); e != nil {
		t.Fatal(e)
	}
	if e = c.Sync(""); e != nil {
		t.Fatal(e)
	}
	t.Log("physical-network activation, signed package and manual sync passed")
	c.mu.Lock()
	profiles := append([]Profile{}, c.s.Profiles...)
	c.mu.Unlock()
	profiles = append(profiles, Builtin())
	for _, mode := range []string{"amnezia", "dns", "turn"} {
		t.Run(mode, func(t *testing.T) {
			id := ""
			for _, p := range profiles {
				if p.Mode == mode {
					id = p.ID
					break
				}
			}
			if id == "" {
				t.Fatal("test account has no requested transport")
			}
			if e := c.Connect(id); e != nil {
				t.Fatal(e)
			}
			defer c.Stop()
			deadline := time.Now().Add(370 * time.Second)
			last := ""
			for time.Now().Before(deadline) {
				v := c.View().(map[string]any)
				phase, _ := v["phase"].(string)
				if phase != last {
					t.Log("phase:", phase)
					last = phase
				}
				if phase == "disconnected" {
					t.Fatal("connection stopped:", v["message"])
				}
				if phase == "connected" {
					client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 35 * time.Second}
					defer client.CloseIdleConnections()
					r, e := client.Get("https://1.1.1.1/cdn-cgi/trace")
					if e != nil {
						t.Fatal("system HTTPS:", e)
					}
					defer r.Body.Close()
					b, e := io.ReadAll(io.LimitReader(r.Body, 4096))
					if e != nil || r.StatusCode != 200 || !strings.Contains(string(b), "ip=") {
						t.Fatal("system HTTPS response invalid")
					}
					t.Log("system HTTPS and controller DNS acceptance passed")
					if e = c.Stop(); e != nil {
						t.Fatal(e)
					}
					return
				}
				time.Sleep(time.Second)
			}
			t.Fatal("transport deadline reached")
		})
	}
}
