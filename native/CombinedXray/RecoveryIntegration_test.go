package libXray

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRecoveryValidationDoesNotStartTunnel(t *testing.T) {
	KindlyTurnStop()
	if message := KindlyRecoveryValidate(`{"version":1,"profiles":[]}`); message == "" {
		t.Fatal("invalid configuration accepted")
	}
	if strings.Contains(KindlyTurnStatus(), `"running":true`) {
		t.Fatal("validation started a transport")
	}
}

func TestNewRuntimeCannotOverlapUnfinishedShutdown(t *testing.T) {
	KindlyTurnStop()
	done := make(chan struct{})
	kindlyTurnState.Lock()
	kindlyTurnState.done = done
	kindlyTurnState.running = false
	kindlyTurnState.Unlock()
	defer func() { close(done); kindlyTurnCanStart() }()
	if kindlyTurnCanStart() {
		t.Fatal("new runtime allowed while old lanes are stopping")
	}
	var status kindlyTurnStatus
	if err := json.Unmarshal([]byte(KindlyTurnStatus()), &status); err != nil {
		t.Fatal(err)
	}
	if status.Ready {
		t.Fatal("stopping transport reported ready")
	}
}

func TestRecoveryListenerMatchesSelectedConnection(t *testing.T) {
	for _, test := range []struct{ listen, want string }{
		{"", "127.0.0.1:9000"},
		{"127.0.0.1:9000", "127.0.0.1:9000"},
		{"127.0.0.1:9001", "127.0.0.1:9001"},
		{"127.0.0.1:12345", "127.0.0.1:9000"},
	} {
		t.Run(test.want+"/"+test.listen, func(t *testing.T) {
			input := `{"version":1,"listen":"` + test.listen + `","profiles":[{"id":"dns","type":"dnstt","dns":{"domain":"t.example.test","public_key":"` + strings.Repeat("01", 32) + `","resolvers":["127.0.0.1:9"]}}]}`
			cfg, err := kindlyRecoveryConfig([]byte(input))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Listen != test.want {
				t.Fatalf("selected connection listens on %q, want %q", cfg.Listen, test.want)
			}
		})
	}
}

func TestRecoveryStartStopCancelsUnresponsiveDNS(t *testing.T) {
	input := `{"provider":"recovery","recovery":{"version":1,"profiles":[{"id":"dns","type":"dnstt","dns":{"domain":"t.example.test","public_key":"` + strings.Repeat("01", 32) + `","resolvers":["127.0.0.1:9"]}}]}}`
	if result := KindlyTurnStart(input); result != 0 {
		t.Fatalf("start result %d", result)
	}
	time.Sleep(20 * time.Millisecond)
	started := time.Now()
	KindlyTurnStop()
	if time.Since(started) > time.Second {
		t.Fatal("recovery shutdown exceeded deadline")
	}
	var status kindlyTurnStatus
	if err := json.Unmarshal([]byte(KindlyTurnStatus()), &status); err != nil {
		t.Fatal(err)
	}
	if status.Running || status.Ready {
		t.Fatal("stopped recovery still reported ready")
	}
}
