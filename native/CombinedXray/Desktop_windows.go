package libXray

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/xtls/xray-core/core"
	xstats "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/tun"
	"runtime/debug"
)

// DesktopStart accepts configuration in memory; private keys never need a plaintext runtime file.
func DesktopStart(raw string) error {
	xrayState.Lock()
	defer xrayState.Unlock()
	desktopStopLocked()
	var r struct {
		AWG *amneziaConfig `json:"tndtun_amnezia"`
	}
	if len(raw) > 12<<20 || json.Unmarshal([]byte(raw), &r) != nil {
		return errors.New("invalid configuration")
	}
	if r.AWG != nil {
		if e := r.AWG.validate(); e != nil {
			return e
		}
		a, e := newAmneziaProxy(*r.AWG, amneziaSOCKSAddress)
		if e != nil {
			return e
		}
		xrayState.amnezia = a
	}
	if err := desktopStartCore(raw); err != nil {
		desktopStopLocked()
		return err
	}
	return nil
}

// DesktopReconfigure replaces the core for the same profile. The already proven
// Amnezia proxy and TURN helper are kept alive across the routing change.
func DesktopReconfigure(raw string) error {
	xrayState.Lock()
	defer xrayState.Unlock()
	if len(raw) > 12<<20 {
		return errors.New("invalid configuration")
	}
	if xrayState.server != nil {
		err := xrayState.server.Close()
		xrayState.server = nil
		if err != nil {
			return err
		}
	}
	return desktopStartCore(raw)
}

func DesktopReleaseSystemRoutes(name string) error { return tun.DesktopReleaseRoutes(name) }
func DesktopPacketFailed(name string) bool         { return tun.DesktopPacketFailed(name) }

func desktopStartCore(raw string) error {
	cfg, e := core.LoadConfig("json", bytes.NewReader([]byte(raw)))
	if e != nil {
		return e
	}
	server, e := core.New(cfg)
	if e == nil {
		e = server.Start()
	}
	if e != nil {
		if server != nil {
			server.Close()
		}
		return e
	}
	xrayState.server = server
	debug.FreeOSMemory()
	return nil
}
func desktopStopLocked() {
	if xrayState.server != nil {
		xrayState.server.Close()
		xrayState.server = nil
	}
	if xrayState.amnezia != nil {
		xrayState.amnezia.Close()
		xrayState.amnezia = nil
	}
}
func DesktopStats() (up, down int64) {
	xrayState.Lock()
	defer xrayState.Unlock()
	if xrayState.server == nil {
		return
	}
	m, ok := xrayState.server.GetFeature(xstats.ManagerType()).(xstats.Manager)
	if !ok {
		return
	}
	for _, tag := range []string{"in_proxy", "health"} {
		if c := m.GetCounter("inbound>>>" + tag + ">>>traffic>>>uplink"); c != nil {
			up += c.Value()
		}
		if c := m.GetCounter("inbound>>>" + tag + ">>>traffic>>>downlink"); c != nil {
			down += c.Value()
		}
	}
	return
}
