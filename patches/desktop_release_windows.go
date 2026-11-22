//go:build windows

package tun

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type desktopAdapter struct {
	device *WindowsTun
	failed atomic.Bool
}

// Instances are registered by their owner process, never by looking up a
// Windows interface by its name. Separate VPN clients cannot release each other's routes.
var desktopAdapters sync.Map

func desktopRegister(t *WindowsTun) {
	desktopAdapters.Store(t.options.Name, &desktopAdapter{device: t})
}

func desktopUnregister(t *WindowsTun) {
	if value, ok := desktopAdapters.Load(t.options.Name); ok && value.(*desktopAdapter).device == t {
		desktopAdapters.CompareAndDelete(t.options.Name, value)
	}
}

func desktopNoteReadFailure(t *WindowsTun) {
	if value, ok := desktopAdapters.Load(t.options.Name); ok {
		if state := value.(*desktopAdapter); state.device == t {
			state.failed.Store(true)
		}
	}
}

func DesktopPacketFailed(name string) bool {
	value, ok := desktopAdapters.Load(name)
	return ok && value.(*desktopAdapter).failed.Load()
}

// DesktopReleaseRoutes releases traffic before Xray waits for its packet
// workers to stop. It is safe to call again during normal cleanup.
func DesktopReleaseRoutes(name string) error {
	value, ok := desktopAdapters.Load(name)
	if !ok {
		return nil
	}
	t := value.(*desktopAdapter).device
	t.Lock()
	defer t.Unlock()
	if t.closed {
		return nil
	}
	var result error
	// The adapter also owns generated connected routes. Only remove the
	// capture prefixes installed by Start, leaving its link addresses intact.
	for _, raw := range t.options.AutoSystemRoutingTable {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		next := netip.IPv6Unspecified()
		if prefix.Addr().Is4() {
			next = netip.IPv4Unspecified()
		}
		err = t.luid.DeleteRoute(prefix.Masked(), next)
		if !errors.Is(err, windows.ERROR_NOT_FOUND) && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			result = errors.Join(result, err)
		}
	}
	if len(t.options.DNS) > 0 {
		for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
			result = errors.Join(result, t.luid.FlushDNS(family))
		}
	}
	return result
}
