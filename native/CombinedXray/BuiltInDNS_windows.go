package libXray

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/KindlyVPN/foundation/transports"
	"kindlyvpn/native/internal/paneldnstt"
)

// The explicit user VPN owns this listener and pool. Panel operations have
// separate pools and never invoke or stop this lifecycle.
func runBuiltInDNS(parent context.Context, input managedDNSConfig, report func(transports.Status)) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	key, err := hex.DecodeString(input.PublicKey)
	if err != nil || len(key) != 32 {
		return errors.New("invalid DNS key")
	}
	budget := paneldnstt.NewQueryBudget(400)
	var pool *transports.StreamPool
	for _, resolver := range input.Resolvers {
		laneCtx, stop := context.WithCancel(ctx)
		type result struct {
			pool *transports.StreamPool
			err  error
		}
		ready := make(chan result, 1)
		go func(resolver string) {
			p, e := transports.OpenStreamPool(laneCtx, input.sessions(), func(attempt context.Context, _ int) (transports.PoolSession, error) {
				wire, address, e := panelDNSWire(attempt, input.PhysicalInterface, resolver)
				if e != nil {
					return nil, e
				}
				session, e := paneldnstt.OpenWithReceiveBuffer(attempt, input.Domain, key, wire, address, budget, 256*1024)
				if e != nil {
					wire.Close()
					return nil, e
				}
				return session, nil
			})
			ready <- result{p, e}
		}(resolver)
		timer := time.NewTimer(30 * time.Second)
		var opened result
		select {
		case opened = <-ready:
		case <-timer.C:
			stop()
			opened = <-ready
		case <-ctx.Done():
			stop()
			opened = <-ready
		}
		timer.Stop()
		if opened.err == nil && opened.pool != nil && laneCtx.Err() == nil {
			pool = opened.pool
			defer stop()
			break
		}
		stop()
		if opened.pool != nil {
			opened.pool.Close()
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	if pool == nil {
		return errors.New("built-in DNS resolvers are unavailable")
	}
	defer pool.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:9002")
	if err != nil {
		return err
	}
	defer listener.Close()
	closeListener := context.AfterFunc(ctx, func() { listener.Close() })
	defer closeListener()
	publish := func() {
		live := pool.LiveCount()
		stage := "authenticated"
		if live == 0 {
			stage = "reconnecting"
		}
		report(transports.Status{Running: true, Ready: live > 0, Stage: stage, Profile: "managed_dns", Transport: "dnstt", ConnectedStreams: live, RequestedStreams: input.sessions()})
	}
	publish()
	statusDone := make(chan struct{})
	go func() {
		defer close(statusDone)
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
	var workers sync.WaitGroup
	defer func() { cancel(); listener.Close(); pool.Close(); workers.Wait(); <-statusDone }()
	slots := make(chan struct{}, 32)
	for {
		local, err := listener.Accept()
		if err != nil {
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			local.Close()
			continue
		}
		workers.Add(1)
		go func(local net.Conn) {
			defer workers.Done()
			defer func() { <-slots }()
			defer local.Close()
			stopLocal := context.AfterFunc(ctx, func() { local.Close() })
			defer stopLocal()
			remote, err := pool.Open(ctx)
			if err != nil {
				return
			}
			defer remote.Close()
			copied := make(chan struct{}, 1)
			go func() { io.Copy(remote, local); remote.Close(); copied <- struct{}{} }()
			io.Copy(local, remote)
			local.Close()
			<-copied
		}(local)
	}
}
