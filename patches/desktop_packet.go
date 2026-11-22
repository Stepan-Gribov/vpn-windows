package tun

import (
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/stats"
)

// Preserve UDP datagram boundaries and destination metadata when statistics
// are enabled. A plain net.Conn counter wrapper erases these interfaces.
type desktopPacketCounters struct {
	net.Conn
	up, down stats.Counter
}

func (c *desktopPacketCounters) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b, e := c.Conn.(buf.Reader).ReadMultiBuffer()
	if c.up != nil {
		c.up.Add(int64(b.Len()))
	}
	return b, e
}
func (c *desktopPacketCounters) WriteMultiBuffer(b buf.MultiBuffer) error {
	n := int64(b.Len())
	e := c.Conn.(buf.Writer).WriteMultiBuffer(b)
	if e == nil && c.down != nil {
		c.down.Add(n)
	}
	return e
}
