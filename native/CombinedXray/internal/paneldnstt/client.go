package paneldnstt

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
)

type Session struct {
	*smux.Session
	stop func()
}

func (s *Session) Close() error { s.stop(); return nil }

// Open authenticates the server over fresh, randomly padded DNS queries before
// returning. UDP socket creation alone is never reported as readiness.
// Open uses an operation-owned physical-network packet connection. It never
// changes a global dialer, user VPN, listener, or native TURN singleton.
func Open(ctx context.Context, domain string, key []byte, wire net.PacketConn, addr net.Addr, budget *QueryBudget) (*Session, error) {
	return OpenWithReceiveBuffer(ctx, domain, key, wire, addr, budget, 1024*1024)
}

func OpenWithReceiveBuffer(ctx context.Context, domain string, key []byte, wire net.PacketConn, addr net.Addr, budget *QueryBudget, receiveBuffer int) (*Session, error) {
	name, err := dns.ParseName(domain)
	if err != nil {
		return nil, err
	}
	mtu := capacity(name) - 8 - 1 - numPadding - 1
	if mtu < 80 {
		return nil, errors.New("DNS zone leaves insufficient payload capacity")
	}
	wire = &pacedPacketConn{PacketConn: wire, budget: budget, ctx: ctx}
	packets := NewDNSPacketConn(wire, addr, name)
	conn, err := kcp.NewConn2(addr, nil, 0, 0, packets)
	if err != nil {
		wire.Close()
		packets.Close()
		return nil, err
	}
	conn.SetStreamMode(true)
	conn.SetNoDelay(0, 0, 0, 1)
	conn.SetWindowSize(64, 64)
	conn.SetMtu(mtu)
	stop := func() { conn.Close(); packets.Close(); wire.Close() }
	onCancel := context.AfterFunc(ctx, stop)
	fail := func(err error) (*Session, error) { onCancel(); stop(); return nil, err }
	conn.SetDeadline(time.Now().Add(12 * time.Second))
	rw, err := noise.NewClient(conn, key)
	if err != nil {
		return fail(errors.New("DNS server authentication failed or timed out"))
	}
	conn.SetDeadline(time.Time{})
	cfg := smux.DefaultConfig()
	cfg.Version = 2
	cfg.KeepAliveTimeout = 45 * time.Second
	cfg.MaxReceiveBuffer = receiveBuffer
	cfg.MaxStreamBuffer = 64 * 1024
	if receiveBuffer < 1024*1024 {
		cfg.MaxStreamBuffer = 32 * 1024
	}
	session, err := smux.Client(rw, cfg)
	if err != nil {
		return fail(err)
	}
	return &Session{Session: session, stop: func() { onCancel(); session.Close(); stop() }}, nil
}

func capacity(domain dns.Name) int {
	n := 254
	for _, label := range domain {
		n -= len(label) + 1
	}
	return n * 63 / 64 * 5 / 8
}

func (s *Session) Done() <-chan struct{} { return s.Session.CloseChan() }
func (s *Session) Open(ctx context.Context) (io.ReadWriteCloser, error) {
	stop := context.AfterFunc(ctx, func() { s.Close() })
	stream, err := s.Session.OpenStream()
	stop()
	if ctx.Err() != nil {
		if stream != nil {
			stream.Close()
		}
		return nil, ctx.Err()
	}
	return stream, err
}
