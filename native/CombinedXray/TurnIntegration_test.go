package libXray

import (
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"
)

func TestLiveVKTURN(t *testing.T) {
	link := os.Getenv("KINDLYVPN_TURN_VK_LINK")
	if link == "" {
		t.Skip("KINDLYVPN_TURN_VK_LINK is not set")
	}
	peer := os.Getenv("KINDLYVPN_TURN_PEER")
	if peer == "" {
		peer = "149.33.14.167:56010"
	}
	listen := "127.0.0.1:19000"
	payload, err := json.Marshal(kindlyTurnConfig{
		Provider:     "vk",
		VKLink:       link,
		PeerAddr:     peer,
		SessionCount: 10,
		UseUDP:       true,
		Listen:       listen,
		WrapKey:      "3c426ec8d79f2a194aff29956ac08738c2dfb0a55afe7424d6425c6c0f5fcf33",
	})
	if err != nil {
		t.Fatal(err)
	}
	if code := KindlyTurnStart(string(payload)); code != 0 {
		t.Fatalf("TURN start returned %d", code)
	}
	defer KindlyTurnStop()

	deadline := time.Now().Add(150 * time.Second)
	lastStatus := ""
	for time.Now().Before(deadline) {
		status := KindlyTurnStatus()
		if status != lastStatus {
			t.Log(status)
			lastStatus = status
		}
		var decoded kindlyTurnStatus
		_ = json.Unmarshal([]byte(status), &decoded)
		if decoded.LastError != "" {
			t.Fatalf("TURN failed: %s", decoded.LastError)
		}
		if decoded.Ready {
			connection, dialErr := net.DialTimeout("tcp", listen, 500*time.Millisecond)
			if dialErr == nil {
				_ = connection.Close()
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("TURN did not expose %s before timeout; final status: %s", listen, lastStatus)
}
