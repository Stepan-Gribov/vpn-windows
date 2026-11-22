package clientcore

import (
	"regexp"
	"strings"
	"sync"
)

var (
	runtimeDetailMu sync.RWMutex
	runtimeDetail   string
	secretInDetail  = regexp.MustCompile(`(?i)((?:session|success|access)_token(?:=|:))[^&\s\]}]+`)
)

func setRuntimeDetail(value string) {
	value = secretInDetail.ReplaceAllString(value, "$1<redacted>")
	value = strings.TrimSpace(value)
	if len(value) > 600 {
		value = value[:600]
	}
	runtimeDetailMu.Lock()
	runtimeDetail = value
	runtimeDetailMu.Unlock()
}

// ConnectedStreamCount is used by the iOS bridge to decide whether UDP TURN
// established and whether it should retry the same settings over TCP.
func ConnectedStreamCount() int32 {
	return connectedStreams.Load()
}

// LocalListenerReady reports that the local VLESS listener is accepting
// connections after the initial TURN lane set has been established.
func LocalListenerReady() bool {
	return vlessListenerReady.Load()
}

// ManualCaptchaPending reports that the embedded helper is serving a VK
// challenge on localhost and is waiting for the app's WebView to complete it.
func ManualCaptchaPending() bool {
	return captchaWaiters.Load() > 0
}

// RuntimeDetail returns the latest recoverable setup error while session
// maintainers continue retrying in the background.
func RuntimeDetail() string {
	runtimeDetailMu.RLock()
	defer runtimeDetailMu.RUnlock()
	return runtimeDetail
}
