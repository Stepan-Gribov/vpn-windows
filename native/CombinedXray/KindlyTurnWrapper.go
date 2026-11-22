package libXray

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/KindlyVPN/foundation/transports"
	"github.com/cacggghp/vk-turn-proxy/pkg/clientcore"
)

type kindlyTurnConfig struct {
	ManagedDNS   json.RawMessage `json:"managed_dns"`
	Recovery     json.RawMessage `json:"recovery"`
	Provider     string          `json:"provider"`
	VKLink       string          `json:"vk_link"`
	MAXToken     string          `json:"max_token"`
	MAXPeerID    string          `json:"max_peer_id"`
	PeerAddr     string          `json:"peer_addr"`
	SessionCount int             `json:"session_count"`
	UseUDP       bool            `json:"use_udp"`
	Listen       string          `json:"listen"`
	WrapKey      string          `json:"wrap_key"`
	AutoCaptcha  bool            `json:"auto_captcha"`
}

type kindlyTurnStatus struct {
	Profile          string `json:"profile,omitempty"`
	Running          bool   `json:"running"`
	Ready            bool   `json:"ready"`
	Transport        string `json:"transport"`
	ConnectedStreams int32  `json:"connected_streams"`
	CaptchaRequired  bool   `json:"captcha_required"`
	CaptchaURL       string `json:"captcha_url,omitempty"`
	Detail           string `json:"detail,omitempty"`
	LastError        string `json:"last_error,omitempty"`
}

var kindlyTurnState struct {
	sync.Mutex
	cancel     context.CancelFunc
	done       chan struct{}
	generation uint64
	running    bool
	transport  string
	lastError  string
	recovery   *transports.Status
}

// KindlyTurnStart starts the bonded local VLESS-to-TURN helper inside the same
// Go runtime as Xray. Keeping both engines in one archive is required on iOS:
// two independent Go c-archives cannot safely be linked into one extension.
func KindlyTurnStart(raw string) int32 {
	var input kindlyTurnConfig
	if err := json.Unmarshal([]byte(raw), &input); err != nil {
		return -2
	}
	if input.Provider == "managed_dns" {
		return kindlyManagedDNSStart(input.ManagedDNS)
	}
	if input.Provider == "recovery" {
		return kindlyRecoveryStart(input.Recovery)
	}
	if input.PeerAddr == "" || (input.Provider == "vk" && input.VKLink == "") ||
		(input.Provider == "max" && (input.MAXToken == "" || input.MAXPeerID == "")) {
		return -3
	}
	switch input.SessionCount {
	case 1, 2, 4, 10, 16:
	default:
		input.SessionCount = 10
	}
	if input.Listen == "" {
		input.Listen = "127.0.0.1:9000"
	}

	KindlyTurnStop()
	if !kindlyTurnCanStart() {
		return -5
	}
	kindlyTurnState.Lock()
	kindlyTurnState.generation++
	generation := kindlyTurnState.generation
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	kindlyTurnState.cancel = cancel
	kindlyTurnState.done = done
	kindlyTurnState.running = true
	kindlyTurnState.recovery = nil
	if input.UseUDP {
		kindlyTurnState.transport = "udp"
	} else {
		kindlyTurnState.transport = "tcp"
	}
	kindlyTurnState.lastError = ""
	kindlyTurnState.Unlock()

	go func() {
		defer close(done)
		kindlyTurnSupervise(ctx, generation, input)
	}()
	return 0
}

func kindlyTurnSupervise(ctx context.Context, generation uint64, input kindlyTurnConfig) {
	cfg := kindlyTurnClientConfig(input)
	if input.UseUDP {
		child, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- clientcore.Run(child, cfg) }()
		deadline := time.Now().Add(45 * time.Second)
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				cancel()
				<-done
				kindlyTurnFinish(generation, nil)
				return
			case err := <-done:
				kindlyTurnFinish(generation, err)
				return
			case <-ticker.C:
				if clientcore.ManualCaptchaPending() {
					// Match Android: never switch transports while the user is
					// completing VK's challenge. Give UDP a fresh readiness window
					// after the challenge has completed.
					deadline = time.Now().Add(30 * time.Second)
					continue
				}
				if time.Now().Before(deadline) {
					continue
				}
				if clientcore.ConnectedStreamCount() > 0 {
					deadline = time.Now().Add(20 * time.Second)
					continue
				}
				cancel()
				<-done
				select {
				case <-ctx.Done():
					kindlyTurnFinish(generation, nil)
					return
				case <-time.After(time.Second):
				}
				cfg.UseUDP = false
				kindlyTurnState.Lock()
				if kindlyTurnState.generation == generation {
					kindlyTurnState.transport = "tcp"
				}
				kindlyTurnState.Unlock()
				break
			}
			break
		}
	}
	err := clientcore.Run(ctx, cfg)
	kindlyTurnFinish(generation, err)
}

func kindlyTurnClientConfig(input kindlyTurnConfig) clientcore.Config {
	return clientcore.Config{
		Listen:         input.Listen,
		VKLink:         input.VKLink,
		MAXToken:       input.MAXToken,
		MAXPeerID:      input.MAXPeerID,
		PeerAddr:       input.PeerAddr,
		NumStreams:     input.SessionCount,
		UseUDP:         input.UseUDP,
		VLESSMode:      true,
		MobileMemory:   true,
		VLESSBond:      true,
		WrapMode:       true,
		WrapKeyHex:     input.WrapKey,
		ManualCaptcha:  input.Provider == "vk" && !input.AutoCaptcha,
		CaptchaSolver:  "v2",
		StreamsPerCred: 10,
	}
}

func kindlyTurnFinish(generation uint64, err error) {
	kindlyTurnState.Lock()
	defer kindlyTurnState.Unlock()
	if kindlyTurnState.generation != generation {
		return
	}
	kindlyTurnState.running = false
	kindlyTurnState.cancel = nil
	kindlyTurnState.done = nil
	if err != nil && err != context.Canceled {
		kindlyTurnState.lastError = err.Error()
	}
}

func KindlyTurnStop() {
	kindlyTurnState.Lock()
	cancel := kindlyTurnState.cancel
	done := kindlyTurnState.done
	kindlyTurnState.cancel = nil
	kindlyTurnState.running = false
	kindlyTurnState.generation++
	kindlyTurnState.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
			kindlyTurnState.Lock()
			if kindlyTurnState.done == done {
				kindlyTurnState.done = nil
			}
			kindlyTurnState.Unlock()
		case <-time.After(5 * time.Second):
		}
	}
}

func kindlyTurnCanStart() bool {
	kindlyTurnState.Lock()
	defer kindlyTurnState.Unlock()
	if kindlyTurnState.done == nil {
		return true
	}
	select {
	case <-kindlyTurnState.done:
		kindlyTurnState.done = nil
		return true
	default:
		return false
	}
}

func KindlyTurnStatus() string {
	kindlyTurnState.Lock()
	if recovery := kindlyTurnState.recovery; recovery != nil {
		status := kindlyTurnStatus{Running: kindlyTurnState.running, Ready: kindlyTurnState.running && recovery.Ready,
			Profile: recovery.Profile, Transport: recovery.Transport, Detail: recovery.Stage, LastError: recovery.Code}
		if status.Ready {
			status.ConnectedStreams = int32(recovery.ConnectedStreams)
			if status.ConnectedStreams == 0 {
				status.ConnectedStreams = 1
			}
		}
		kindlyTurnState.Unlock()
		data, _ := json.Marshal(status)
		return string(data)
	}
	captchaRequired := clientcore.ManualCaptchaPending()
	status := kindlyTurnStatus{
		Running:          kindlyTurnState.running,
		Ready:            kindlyTurnState.running && clientcore.ConnectedStreamCount() > 0 && clientcore.LocalListenerReady(),
		Transport:        kindlyTurnState.transport,
		ConnectedStreams: clientcore.ConnectedStreamCount(),
		CaptchaRequired:  captchaRequired,
		Detail:           clientcore.RuntimeDetail(),
		LastError:        kindlyTurnState.lastError,
	}
	if captchaRequired {
		status.CaptchaURL = "http://localhost:8765/"
	}
	kindlyTurnState.Unlock()
	data, _ := json.Marshal(status)
	return string(data)
}

func kindlyRecoveryStart(raw []byte) int32 {
	cfg, err := kindlyRecoveryConfig(raw)
	if err != nil {
		return -4
	}
	KindlyTurnStop()
	if !kindlyTurnCanStart() {
		return -5
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	kindlyTurnState.Lock()
	kindlyTurnState.generation++
	generation := kindlyTurnState.generation
	kindlyTurnState.cancel = cancel
	kindlyTurnState.done = done
	kindlyTurnState.running = true
	kindlyTurnState.lastError = ""
	kindlyTurnState.recovery = &transports.Status{Running: true, Stage: "starting"}
	kindlyTurnState.Unlock()
	go func() {
		defer close(done)
		err := transports.Run(ctx, cfg, func(status transports.Status) {
			kindlyTurnState.Lock()
			defer kindlyTurnState.Unlock()
			if generation == kindlyTurnState.generation {
				kindlyTurnState.recovery = &status
			}
		})
		kindlyTurnFinish(generation, err)
	}()
	return 0
}

func kindlyRecoveryConfig(raw []byte) (transports.Config, error) {
	cfg, err := transports.ParseConfig(raw)
	if err != nil {
		return cfg, err
	}
	// The selectable DNS connection has its own local VLESS port. Preserve it
	// while keeping operator imports on the app's regular recovery listener.
	if cfg.Listen != "127.0.0.1:9001" {
		cfg.Listen = "127.0.0.1:9000"
	}
	return cfg, nil
}

// Validation never starts a transport or changes the running tunnel.
func KindlyRecoveryValidate(raw string) string {
	_, err := transports.ParseConfig([]byte(raw))
	if err != nil {
		return err.Error()
	}
	return ""
}
