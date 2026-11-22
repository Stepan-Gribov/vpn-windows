package libXray

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"runtime/debug"
	"strconv"
	"sync"

	"github.com/xtls/xray-core/common/cmdarg"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/proxy/tun"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type runXrayRequest struct {
	DatDir     string `json:"datDir"`
	ConfigPath string `json:"configPath"`
}

type callResponse struct {
	Success bool   `json:"success"`
	Data    any    `json:"data,omitempty"`
	Error   string `json:"error,omitempty"`
}

var xrayState struct {
	sync.Mutex
	server  *core.Instance
	amnezia *amneziaProxy
}

func encodeResponse(data any, err error) string {
	response := callResponse{Success: err == nil, Data: data}
	if err != nil {
		response.Error = err.Error()
	}
	raw, marshalErr := json.Marshal(response)
	if marshalErr != nil {
		raw = []byte(`{"success":false,"error":"response encoding failed"}`)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func decodeRunRequest(value string) (runXrayRequest, error) {
	var request runXrayRequest
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return request, err
	}
	if err := json.Unmarshal(raw, &request); err != nil {
		return request, err
	}
	if request.ConfigPath == "" {
		return request, errors.New("configPath is empty")
	}
	return request, nil
}

func prepareEnvironment(dataDir string) {
	if dataDir != "" {
		_ = os.Setenv(platform.AssetLocation, dataDir)
		_ = os.Setenv(platform.CertLocation, dataDir)
	}
}

func makeServer(request runXrayRequest) (*core.Instance, error) {
	prepareEnvironment(request.DatDir)
	configuration, err := core.LoadConfig("json", cmdarg.Arg{request.ConfigPath})
	if err != nil {
		return nil, err
	}
	return core.New(configuration)
}

func SetTunFd(fd int32) {
	_ = os.Setenv(platform.TunFdKey, strconv.Itoa(int(fd)))
}

// SetIPv6Enabled applies to the TUN listener before starting its packet stack.
// Disabled IPv6 is rejected at connection setup rather than after TCP succeeds.
func SetIPv6Enabled(enabled bool) {
	tun.SetIPv6Enabled(enabled)
}

func SetMemoryLimitMB(mb int64) {
	if mb > 0 {
		debug.SetMemoryLimit(mb * 1024 * 1024)
	}
}

// FreeMemory returns unused heap pages to the OS. GOMEMLIMIT is a soft Go
// target; the extension's hard budget also includes Swift and resident code.
func FreeMemory() {
	debug.FreeOSMemory()
}

func SetTCPBufMaxKB(kb int32) {
	if kb > 0 {
		tun.SetTCPBufMaxKB(int(kb))
	}
}

func SetTCPMaxInFlight(count int32) {
	if count > 0 {
		tun.SetTCPMaxInFlight(int(count))
	}
}

func SetMaxUDPConns(count int32) {
	if count > 0 {
		tun.SetMaxUDPConns(int(count))
	}
}

func GetFreePorts(count int) string {
	if count < 1 {
		return encodeResponse(nil, errors.New("count must be positive"))
	}
	listeners := make([]net.Listener, 0, count)
	ports := make([]int, 0, count)
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	for range count {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return encodeResponse(nil, err)
		}
		listeners = append(listeners, listener)
		ports = append(ports, listener.Addr().(*net.TCPAddr).Port)
	}
	return encodeResponse(map[string]any{"ports": ports}, nil)
}

func RunXray(base64Request string) string {
	request, err := decodeRunRequest(base64Request)
	if err != nil {
		return encodeResponse(false, err)
	}

	xrayState.Lock()
	defer xrayState.Unlock()
	if xrayState.server != nil {
		_ = xrayState.server.Close()
		xrayState.server = nil
	}
	if xrayState.amnezia != nil {
		xrayState.amnezia.Close()
		xrayState.amnezia = nil
	}
	awg, err := amneziaFromFile(request.ConfigPath)
	if err != nil {
		return encodeResponse(false, err)
	}
	if awg != nil {
		xrayState.amnezia, err = newAmneziaProxy(*awg, amneziaSOCKSAddress)
		if err != nil {
			return encodeResponse(false, err)
		}
	}
	server, err := makeServer(request)
	if err == nil {
		err = server.Start()
	}
	if err != nil {
		if server != nil {
			_ = server.Close()
		}
		if xrayState.amnezia != nil {
			xrayState.amnezia.Close()
			xrayState.amnezia = nil
		}
		return encodeResponse(false, err)
	}
	xrayState.server = server
	debug.FreeOSMemory()
	return encodeResponse(true, nil)
}

func StopXray() string {
	xrayState.Lock()
	defer xrayState.Unlock()
	var err error
	if xrayState.server != nil {
		err = xrayState.server.Close()
		xrayState.server = nil
	}
	if xrayState.amnezia != nil {
		xrayState.amnezia.Close()
		xrayState.amnezia = nil
	}
	tls.ResetSessionCache()
	debug.FreeOSMemory()
	return encodeResponse(err == nil, err)
}

func TestXray(base64Request string) string {
	request, err := decodeRunRequest(base64Request)
	if err != nil {
		return encodeResponse("", err)
	}
	if _, err := amneziaFromFile(request.ConfigPath); err != nil {
		return encodeResponse("", err)
	}
	server, err := makeServer(request)
	if server != nil {
		closeErr := server.Close()
		if err == nil {
			err = closeErr
		}
	}
	return encodeResponse("", err)
}

func XrayVersion() string {
	return encodeResponse(core.Version(), nil)
}

// Share-link parsing is implemented in Swift so it stays identical to the
// Android import rules. The symbol remains available for API compatibility.
func ConvertShareLinksToXrayJson(_ string) string {
	return encodeResponse(nil, errors.New("share-link conversion is handled by the app"))
}

// AmneziaRefreshSockets handles a physical path/wake event without restarting
// the VPN, polling reachability or changing split routing.
func AmneziaRefreshSockets() bool {
	xrayState.Lock()
	defer xrayState.Unlock()
	return xrayState.amnezia != nil && xrayState.amnezia.networkChanged()
}
