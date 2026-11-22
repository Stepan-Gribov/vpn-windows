package dnsttclient

import (
	"context"
	"net"
	"sync"
	"time"
)

// QueryBudget paces actual outgoing DNS packets across all authenticated lanes,
// including polls and retransmissions, rather than multiplying QPS per lane.
type QueryBudget struct {
	mu       sync.Mutex
	next     time.Time
	interval time.Duration
}

func NewQueryBudget(maxQPS int) *QueryBudget {
	if maxQPS < 1 {
		maxQPS = 1
	}
	return &QueryBudget{interval: time.Second / time.Duration(maxQPS)}
}

func (b *QueryBudget) wait(ctx context.Context) error {
	b.mu.Lock()
	now := time.Now()
	if b.next.Before(now) {
		b.next = now
	}
	at := b.next
	b.next = at.Add(b.interval)
	b.mu.Unlock()
	timer := time.NewTimer(time.Until(at))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}

type pacedPacketConn struct {
	net.PacketConn
	budget *QueryBudget
	ctx    context.Context
}

func (c *pacedPacketConn) WriteTo(packet []byte, address net.Addr) (int, error) {
	if err := c.budget.wait(c.ctx); err != nil {
		return 0, err
	}
	return c.PacketConn.WriteTo(packet, address)
}
