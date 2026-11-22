//go:build conference

package transports

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/KindlyVPN/foundation/transports/bootstrap"
	"github.com/openlibrecommunity/olcrtc/pkg/olcrtc/client"
	"github.com/openlibrecommunity/olcrtc/pkg/olcrtc/tunnel"
	"golang.org/x/net/proxy"
)

type conferenceSession struct {
	dialer proxy.ContextDialer
	target string
	done   chan struct{}
	cancel context.CancelFunc
}

const ConferenceAvailable = true

func (s *conferenceSession) Open(ctx context.Context) (io.ReadWriteCloser, error) {
	return s.dialer.DialContext(ctx, "tcp", s.target)
}
func (s *conferenceSession) Done() <-chan struct{} { return s.done }
func (s *conferenceSession) Close() error          { s.cancel(); return nil }

func openConference(ctx context.Context, cfg ConferenceConfig, resolvers []string) (session, error) {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	ready := make(chan string, 1)
	c := client.New(client.Config{
		Provider: cfg.Provider, RoomURL: cfg.Room, KeyHex: cfg.Key,
		Transport: cfg.Channel, LocalAddr: "127.0.0.1:0",
		Resolver: conferenceResolver(resolvers),
		DeviceID: rand.Text(), // unique per connection, never a hardware identifier
		Liveness: client.LivenessConfig{Interval: 10 * time.Second, Timeout: 10 * time.Second, Failures: 3},
	})
	go func() {
		defer close(done)
		c.RunWithAddress(ctx, func(addr string) {
			select {
			case ready <- addr:
			default:
			}
		})
	}()
	timer := time.NewTimer(60 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		cancel()
		return nil, ctx.Err()
	case <-done:
		cancel()
		return nil, errors.New("conference negotiation failed")
	case <-timer.C:
		cancel()
		return nil, errors.New("conference negotiation timed out")
	case addr := <-ready:
		dialer, err := proxy.SOCKS5("tcp", addr, nil, &net.Dialer{Timeout: 10 * time.Second})
		if err != nil {
			cancel()
			return nil, err
		}
		s := &conferenceSession{dialer: dialer.(proxy.ContextDialer), target: cfg.Target, done: done, cancel: cancel}
		probeCtx, stop := context.WithTimeout(ctx, 15*time.Second)
		probe, err := s.Open(probeCtx)
		stop()
		if err != nil {
			cancel()
			return nil, errors.New("conference encrypted route probe failed")
		}
		probe.Close()
		return s, nil
	}
}

// RunConferenceServer forces all upstream CONNECT requests through a local
// allow-only SOCKS gate. The room key never grants unrestricted proxy access:
// the fixed target still authenticates each customer's VLESS subscription.
func RunConferenceServer(ctx context.Context, cfg ConferenceConfig, resolvers []string) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	gate, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer gate.Close()
	stop := context.AfterFunc(ctx, func() { gate.Close() })
	defer stop()
	go serveSOCKSGate(ctx, gate, cfg.Target)
	host, port, _ := net.SplitHostPort(gate.Addr().String())
	n, _ := strconv.Atoi(port)
	return tunnel.New(tunnel.Config{
		Provider: cfg.Provider, RoomURL: cfg.Room, KeyHex: cfg.Key,
		Transport: cfg.Channel, Resolver: conferenceResolver(resolvers),
		SOCKSProxyAddr: host, SOCKSProxyPort: n,
		Liveness: tunnel.LivenessConfig{Interval: 10 * time.Second, Timeout: 10 * time.Second, Failures: 3},
	}).Run(ctx)
}

func conferenceResolver(servers []string) *net.Resolver {
	if resolver := bootstrap.Resolver(servers); resolver != nil {
		return resolver
	}
	// Pass a non-nil resolver so provider defaults cannot substitute public DNS.
	return net.DefaultResolver
}
