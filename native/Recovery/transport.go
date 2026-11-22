package transports

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/KindlyVPN/foundation/transports/internal/dnsttclient"
	"github.com/xtaci/smux"
)

// Status is deliberately safe to export. No room URLs, keys, resolver addresses,
// subscription URLs or user destinations are included.
type Status struct {
	ConnectedStreams int    `json:"connected_streams,omitempty"`
	RequestedStreams int    `json:"requested_streams,omitempty"`
	Running          bool   `json:"running"`
	Ready            bool   `json:"ready"`
	Profile          string `json:"profile,omitempty"`
	Transport        string `json:"transport,omitempty"`
	Stage            string `json:"stage"`
	Code             string `json:"code,omitempty"`
}

type session interface {
	Open(context.Context) (io.ReadWriteCloser, error)
	Done() <-chan struct{}
	Close() error
}

type dnsSession struct{ *dnsttclient.Session }

func (s dnsSession) Open(ctx context.Context) (io.ReadWriteCloser, error) {
	return openMuxStream(ctx, s.Session.Session)
}
func (s dnsSession) Done() <-chan struct{} { return s.CloseChan() }

// smux has no context-aware OpenStream. A blocked control frame means the
// carrier cannot carry new traffic; close it on timeout so the supervisor can
// select the next route rather than leave local connections waiting forever.
func openMuxStream(ctx context.Context, s *smux.Session) (io.ReadWriteCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { s.Close() })
	defer stop()
	stream, err := s.OpenStream()
	if ctx.Err() != nil {
		if stream != nil {
			stream.Close()
		}
		return nil, ctx.Err()
	}
	if err != nil {
		s.Close()
		return nil, err
	}
	return stream, nil
}

// Run owns the loopback listener and all active streams. Each round tries every
// configured first hop, in order; DNS resolvers are tried independently. Stops
// after two rounds so the app's existing bounded reconnect policy stays in charge.
// Existing TCP streams end when a route changes; they are never silently replayed.
func Run(ctx context.Context, cfg Config, report func(Status)) error {
	return run(ctx, cfg, report, connect)
}

func run(ctx context.Context, cfg Config, report func(Status), open func(context.Context, Config, Profile) (session, error)) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	// The VPN core feeds back a route that authenticated but did not carry its
	// probe. Continue after that route on reconnect, rather than selecting the
	// same unusable first hop forever merely because its handshake succeeded.
	for index, profile := range cfg.Profiles {
		if profile.ID == cfg.StartAfter {
			cfg.Profiles = append(append([]Profile{}, cfg.Profiles[index+1:]...), cfg.Profiles[:index+1]...)
			break
		}
	}
	if report == nil {
		report = func(Status) {}
	}
	defer report(Status{Stage: "stopped"})
	for round := 0; round < 2; round++ {
		for _, p := range cfg.Profiles {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			report(Status{Running: true, Profile: p.ID, Transport: p.Type, Stage: "connecting"})
			s, err := open(ctx, cfg, p)
			if err != nil {
				report(Status{Running: true, Profile: p.ID, Transport: p.Type, Stage: "failed", Code: "transport_unreachable_or_authentication_failed"})
				continue
			}
			listener, err := net.Listen("tcp", cfg.Listen)
			if err != nil {
				s.Close()
				return errors.New("local recovery listener unavailable")
			}
			publish := func() {
				live, requested := 1, 1
				if pool, ok := s.(*StreamPool); ok {
					live = pool.LiveCount()
					requested = p.DNS.SessionCount
				}
				stage := "authenticated"
				if live == 0 {
					stage = "reconnecting"
				}
				report(Status{Running: true, Ready: live > 0, Profile: p.ID, Transport: p.Type, Stage: stage, ConnectedStreams: live, RequestedStreams: requested})
			}
			publish()
			serveSession(ctx, listener, s, publish)
			report(Status{Running: true, Profile: p.ID, Transport: p.Type, Stage: "reconnecting", Code: "transport_closed"})
		}
		if round == 0 {
			report(Status{Running: true, Stage: "cooldown"})
			timer := time.NewTimer(20 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return errors.New("all configured recovery routes failed")
}

func connect(ctx context.Context, cfg Config, p Profile) (session, error) {
	switch p.Type {
	case "dnstt":
		key, _ := hex.DecodeString(p.DNS.PublicKey)
		if p.DNS.SessionCount > 0 {
			qps := p.DNS.MaxQPS
			if qps == 0 {
				qps = 800
			}
			budget := NewDNSQueryBudget(qps)
			dns := *p.DNS
			dns.Resolvers = ResolverCandidates(cfg.BootstrapDNS, p.DNS.Resolvers)
			return OpenStreamPool(ctx, p.DNS.SessionCount, func(attempt context.Context, index int) (PoolSession, error) {
				return OpenDNSCarrier(attempt, dns, budget, index)
			})
		}
		for _, resolver := range ResolverCandidates(cfg.BootstrapDNS, p.DNS.Resolvers) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			s, err := dnsttclient.Open(ctx, resolver, p.DNS.Domain, key)
			if err == nil {
				return dnsSession{s}, nil
			}
		}
		return nil, errors.New("no reachable recursive DNS tunnel")
	case "https":
		return openHTTPS(ctx, *p.HTTPS, cfg.BootstrapDNS)
	case "conference":
		return openConference(ctx, *p.Conference, cfg.BootstrapDNS)
	default:
		return nil, errors.New("unknown transport")
	}
}

func serveSession(ctx context.Context, listener net.Listener, s session, publish func()) {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() { cancel(); listener.Close(); s.Close(); wg.Wait() }()
	go func() {
		select {
		case <-ctx.Done():
		case <-s.Done():
		}
		cancel()
		listener.Close()
	}()
	capacity := 16
	if pool, ok := s.(*StreamPool); ok {
		capacity = 32
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-pool.Changes():
					if ctx.Err() == nil {
						publish()
					}
				}
			}
		}()
	}
	limit := make(chan struct{}, capacity)
	for {
		local, err := listener.Accept()
		if err != nil {
			return
		}
		select {
		case limit <- struct{}{}:
		default:
			local.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-limit }()
			defer local.Close()
			openCtx, stop := context.WithTimeout(ctx, 15*time.Second)
			remote, err := s.Open(openCtx)
			stop()
			if err != nil {
				return
			}
			defer remote.Close()
			copyStream(ctx, local, remote)
		}()
	}
}

func copyStream(ctx context.Context, a, b io.ReadWriteCloser) {
	stop := context.AfterFunc(ctx, func() { a.Close(); b.Close() })
	defer stop()
	done := make(chan struct{})
	go func() { io.Copy(a, b); a.Close(); b.Close(); close(done) }()
	io.Copy(b, a)
	a.Close()
	b.Close()
	<-done
}
