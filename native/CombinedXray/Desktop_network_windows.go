package libXray

import (
	"context"
	"encoding/hex"
	"errors"
	"github.com/KindlyVPN/foundation/transports"
	awgconn "github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/cacggghp/vk-turn-proxy/pkg/clientcore"
	"github.com/xtls/xray-core/proxy/tun"
	"kindlyvpn/native/internal/paneldnstt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var physicalIndex atomic.Uint32
var physicalResolverOnce sync.Once
var physicalResolverState struct {
	sync.RWMutex
	control   func(string, string, syscall.RawConn) error
	resolvers []string
}

type desktopBind struct{ awgconn.Bind }

func (b *desktopBind) Open(port uint16) ([]awgconn.ReceiveFunc, uint16, error) {
	f, p, e := b.Bind.Open(port)
	if e != nil {
		return f, p, e
	}
	i := physicalIndex.Load()
	if i != 0 {
		v, ok := b.Bind.(awgconn.BindSocketToInterface)
		if !ok {
			b.Bind.Close()
			return nil, 0, errors.New("interface binding unavailable")
		}
		if e = v.BindSocketToInterface4(i, false); e != nil {
			b.Bind.Close()
			return nil, 0, e
		}
		if e = v.BindSocketToInterface6(i, false); e != nil {
			b.Bind.Close()
			return nil, 0, e
		}
	}
	return f, p, nil
}
func newDesktopAwareBind() awgconn.Bind { return &desktopBind{awgconn.NewDefaultBind()} }
func DesktopPhysicalNetwork(name string, resolvers []string) error {
	iface, e := net.InterfaceByName(name)
	if e != nil {
		return e
	}
	control, e := panelControl(name)
	if e != nil {
		return e
	}
	physicalIndex.Store(uint32(iface.Index))
	clientcore.SetPhysicalSocketControl(control)
	physicalResolverState.Lock()
	physicalResolverState.control = control
	physicalResolverState.resolvers = append([]string{}, resolvers...)
	physicalResolverState.Unlock()
	physicalResolverOnce.Do(func() {
		net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			physicalResolverState.RLock()
			c := physicalResolverState.control
			rs := append([]string{}, physicalResolverState.resolvers...)
			physicalResolverState.RUnlock()
			d := net.Dialer{Control: c, Timeout: 3 * time.Second}
			for _, s := range rs {
				if conn, e := d.DialContext(ctx, network, s); e == nil {
					return conn, nil
				}
			}
			return nil, errors.New("physical DNS unavailable")
		}}
	})
	tun.SetDesktopPhysicalInterface(name)

	return nil
}
func openManagedCarrier(ctx context.Context, input managedDNSConfig, d transports.DNSConfig, b *transports.DNSQueryBudget, i int) (transports.PoolSession, error) {
	if input.PhysicalInterface == "" {
		return transports.OpenDNSCarrier(ctx, d, b, i)
	}
	key, e := hex.DecodeString(input.PublicKey)
	if e != nil {
		return nil, e
	}
	resolvers := input.Resolvers
	if len(resolvers) == 0 {
		resolvers = []string{input.Resolver}
	}
	var last error
	for _, r := range resolvers {
		wire, addr, e := panelDNSWire(ctx, input.PhysicalInterface, r)
		if e != nil {
			last = e
			continue
		}
		s, e := paneldnstt.OpenWithReceiveBuffer(ctx, input.Domain, key, wire, addr, paneldnstt.NewQueryBudget(400), 256*1024)
		if e == nil {
			return s, nil
		}
		wire.Close()
		last = e
	}
	return nil, last
}
