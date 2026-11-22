//go:build ios

package main

/*
#include <stdint.h>
#include <stdlib.h>

__attribute__((constructor))
static void kindly_turn_runtime_setup(void) {
    setenv("GODEBUG", "asyncpreemptoff=1", 1);
}
*/
import "C"

import (
	"context"
	"encoding/json"
	"sync"
	"time"
	"unsafe"

	"github.com/cacggghp/vk-turn-proxy/pkg/clientcore"
)

type bridgeConfig struct {
	Provider     string `json:"provider"`
	VKLink       string `json:"vk_link"`
	MAXToken     string `json:"max_token"`
	MAXPeerID    string `json:"max_peer_id"`
	PeerAddr     string `json:"peer_addr"`
	SessionCount int    `json:"session_count"`
	UseUDP       bool   `json:"use_udp"`
	Listen       string `json:"listen"`
	WrapKey      string `json:"wrap_key"`
}

type bridgeStatus struct {
	Running          bool   `json:"running"`
	Ready            bool   `json:"ready"`
	Transport        string `json:"transport"`
	ConnectedStreams int32  `json:"connected_streams"`
	LastError        string `json:"last_error,omitempty"`
}

var bridgeState struct {
	sync.Mutex
	cancel     context.CancelFunc
	generation uint64
	running    bool
	transport  string
	lastError  string
}

//export KindlyTurnStart
func KindlyTurnStart(raw *C.char) C.int32_t {
	if raw == nil {
		return -1
	}
	var input bridgeConfig
	if err := json.Unmarshal([]byte(C.GoString(raw)), &input); err != nil {
		return -2
	}
	if input.PeerAddr == "" || (input.Provider == "vk" && input.VKLink == "") ||
		(input.Provider == "max" && (input.MAXToken == "" || input.MAXPeerID == "")) {
		return -3
	}
	if input.SessionCount != 16 {
		input.SessionCount = 10
	}
	if input.Listen == "" {
		input.Listen = "127.0.0.1:9000"
	}

	KindlyTurnStop()
	bridgeState.Lock()
	bridgeState.generation++
	generation := bridgeState.generation
	ctx, cancel := context.WithCancel(context.Background())
	bridgeState.cancel = cancel
	bridgeState.running = true
	bridgeState.transport = map[bool]string{true: "udp", false: "tcp"}[input.UseUDP]
	bridgeState.lastError = ""
	bridgeState.Unlock()

	go supervise(ctx, generation, input)
	return 0
}

func supervise(ctx context.Context, generation uint64, input bridgeConfig) {
	cfg := makeClientConfig(input)
	if input.UseUDP {
		child, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- clientcore.Run(child, cfg) }()
		select {
		case <-ctx.Done():
			cancel()
			<-done
			finishGeneration(generation, nil)
			return
		case err := <-done:
			finishGeneration(generation, err)
			return
		case <-time.After(45 * time.Second):
			if clientcore.ConnectedStreamCount() > 0 {
				select {
				case <-ctx.Done(): cancel(); <-done; finishGeneration(generation, nil)
				case err := <-done: finishGeneration(generation, err)
				}
				return
			}
			cancel()
			<-done
			select {
			case <-ctx.Done(): finishGeneration(generation, nil); return
			case <-time.After(time.Second):
			}
			cfg.UseUDP = false
			bridgeState.Lock()
			if bridgeState.generation == generation { bridgeState.transport = "tcp" }
			bridgeState.Unlock()
		}
	}
	err := clientcore.Run(ctx, cfg)
	finishGeneration(generation, err)
}

func makeClientConfig(input bridgeConfig) clientcore.Config {
	return clientcore.Config{
		Listen:         input.Listen,
		VKLink:         input.VKLink,
		MAXToken:       input.MAXToken,
		MAXPeerID:      input.MAXPeerID,
		PeerAddr:       input.PeerAddr,
		NumStreams:     input.SessionCount,
		UseUDP:         input.UseUDP,
		VLESSMode:      true,
		VLESSBond:      true,
		WrapMode:       true,
		WrapKeyHex:     input.WrapKey,
		ManualCaptcha:  input.Provider == "vk",
		CaptchaSolver:  "v2",
		StreamsPerCred: 10,
	}
}

func finishGeneration(generation uint64, err error) {
	bridgeState.Lock()
	defer bridgeState.Unlock()
	if bridgeState.generation != generation {
		return
	}
	bridgeState.running = false
	bridgeState.cancel = nil
	if err != nil && err != context.Canceled {
		bridgeState.lastError = err.Error()
	}
}

//export KindlyTurnStop
func KindlyTurnStop() {
	bridgeState.Lock()
	cancel := bridgeState.cancel
	bridgeState.cancel = nil
	bridgeState.running = false
	bridgeState.generation++
	bridgeState.Unlock()
	if cancel != nil {
		cancel()
	}
}

//export KindlyTurnCopyStatus
func KindlyTurnCopyStatus() *C.char {
	bridgeState.Lock()
	status := bridgeStatus{
		Running:          bridgeState.running,
		Ready:            clientcore.ConnectedStreamCount() > 0,
		Transport:        bridgeState.transport,
		ConnectedStreams: clientcore.ConnectedStreamCount(),
		LastError:        bridgeState.lastError,
	}
	bridgeState.Unlock()
	data, _ := json.Marshal(status)
	return C.CString(string(data))
}

//export KindlyTurnFree
func KindlyTurnFree(pointer unsafe.Pointer) {
	C.free(pointer)
}

func main() {}

