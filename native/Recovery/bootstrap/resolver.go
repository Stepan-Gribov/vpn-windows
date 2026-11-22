// Package bootstrap resolves transport endpoints over explicit underlying-network
// resolvers. Ordinary destination DNS remains the VPN core's responsibility.
package bootstrap

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const attemptTimeout = 2 * time.Second

// Resolver returns nil when no explicit DNS was supplied, preserving the OS
// resolver. No public DNS service is hardcoded and net.DefaultResolver is untouched.
func Resolver(servers []string) *net.Resolver {
	if len(servers) == 0 {
		return nil
	}
	servers = append([]string(nil), servers...)
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return &exchangeConn{ctx: ctx, servers: servers}, nil
	}}
}

// exchangeConn implements PacketConn as well as Conn so Go sends raw DNS
// datagrams. Failover happens when exchanging the query, never on UDP Dial.
type exchangeConn struct {
	mu       sync.Mutex
	ctx      context.Context
	servers  []string
	query    []byte
	deadline time.Time
	closed   bool
	cancel   context.CancelFunc
}

func (c *exchangeConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	c.query = append([]byte(nil), p...)
	return len(p), nil
}

func (c *exchangeConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	query := append([]byte(nil), c.query...)
	ctx, cancel := context.WithCancel(c.ctx)
	if !c.deadline.IsZero() {
		cancel()
		ctx, cancel = context.WithDeadline(c.ctx, c.deadline)
	}
	c.cancel = cancel
	c.mu.Unlock()
	defer cancel()
	m := new(dns.Msg)
	if m.Unpack(query) != nil || len(m.Question) != 1 {
		return 0, errors.New("invalid DNS request")
	}
	for _, server := range c.servers {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		attempt, stop := context.WithTimeout(ctx, attemptTimeout)
		client := &dns.Client{Net: "udp", Timeout: attemptTimeout}
		answer, _, err := client.ExchangeContext(attempt, m, server)
		if err == nil && answer.Truncated {
			client.Net = "tcp"
			answer, _, err = client.ExchangeContext(attempt, m, server)
		}
		stop()
		if err != nil || !answer.Response || answer.Truncated || answer.Id != m.Id || len(answer.Question) != 1 || answer.Question[0] != m.Question[0] || (answer.Rcode != dns.RcodeSuccess && answer.Rcode != dns.RcodeNameError) {
			continue
		}
		wire, err := answer.Pack()
		if err != nil {
			continue
		}
		if len(wire) > len(p) {
			return 0, io.ErrShortBuffer
		}
		return copy(p, wire), nil
	}
	return 0, errors.New("no bootstrap resolver returned a valid response")
}

func (c *exchangeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}
func (c *exchangeConn) LocalAddr() net.Addr  { return &net.UDPAddr{} }
func (c *exchangeConn) RemoteAddr() net.Addr { return &net.UDPAddr{} }
func (c *exchangeConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	return nil
}
func (c *exchangeConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *exchangeConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }
func (c *exchangeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	return n, c.RemoteAddr(), err
}
func (c *exchangeConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }
