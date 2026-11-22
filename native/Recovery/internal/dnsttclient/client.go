package dnsttclient

import (
	"context"
	"errors"
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
func Open(ctx context.Context, resolver, domain string, key []byte) (*Session, error) {
	return OpenWithBudget(ctx, resolver, domain, key, nil)
}

func OpenWithBudget(ctx context.Context, resolver, domain string, key []byte, budget *QueryBudget) (*Session, error) {
	name, err := dns.ParseName(domain)
	if err != nil {
		return nil, err
	}
	mtu := capacity(name) - 8 - 1 - numPadding - 1
	if mtu < 80 {
		return nil, errors.New("DNS zone leaves insufficient payload capacity")
	}
	addr, err := net.ResolveUDPAddr("udp", resolver) // callers require a literal IP
	if err != nil {
		return nil, err
	}
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	var wire net.PacketConn = udp
	if budget != nil {
		wire = &pacedPacketConn{PacketConn: udp, budget: budget, ctx: ctx}
	}
	packets := NewDNSPacketConn(wire, addr, name)
	conn, err := kcp.NewConn2(addr, nil, 0, 0, packets)
	if err != nil {
		udp.Close()
		packets.Close()
		return nil, err
	}
	conn.SetStreamMode(true)
	conn.SetNoDelay(0, 0, 0, 1)
	conn.SetWindowSize(64, 64)
	conn.SetMtu(mtu)
	stop := func() { conn.Close(); packets.Close(); udp.Close() }
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
	cfg.MaxReceiveBuffer = 1024 * 1024
	cfg.MaxStreamBuffer = 64 * 1024
	if budget != nil {
		cfg.MaxReceiveBuffer = 256 * 1024
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
