//go:build !windows

package libXray

import (
	"context"
	"github.com/KindlyVPN/foundation/transports"
	awgconn "github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

func newDesktopAwareBind() awgconn.Bind { return awgconn.NewDefaultBind() }
func openManagedCarrier(c context.Context, _ managedDNSConfig, d transports.DNSConfig, b *transports.DNSQueryBudget, i int) (transports.PoolSession, error) {
	return transports.OpenDNSCarrier(c, d, b, i)
}
