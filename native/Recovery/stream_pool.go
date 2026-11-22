package transports

import (
	"context"
	"errors"
	"io"
	"math/rand"
	"sync"
	"time"
)

// PoolSession is an authenticated carrier. Each application stream stays on its
// chosen carrier for its entire lifetime; bytes are never replayed after failure.
type PoolSession interface {
	Open(context.Context) (io.ReadWriteCloser, error)
	Done() <-chan struct{}
	Close() error
}

type poolLane struct {
	session PoolSession
	active  int
}

// StreamPool follows the Android DNSTT pool: independent reconnecting lanes,
// least-loaded selection with round-robin ties, and staggered handshakes.
type StreamPool struct {
	mu      sync.Mutex
	lanes   []*poolLane
	cursor  int
	cancel  context.CancelFunc
	done    chan struct{}
	changes chan struct{}
}

func OpenStreamPool(parent context.Context, count int, open func(context.Context, int) (PoolSession, error)) (*StreamPool, error) {
	if count < 1 || count > 8 {
		return nil, errors.New("stream pool requires between one and eight lanes")
	}
	ctx, cancel := context.WithCancel(parent)
	p := &StreamPool{cancel: cancel, done: make(chan struct{}), changes: make(chan struct{}, 1)}
	ready := make(chan struct{})
	var first sync.Once
	var workers sync.WaitGroup
	for index := 0; index < count; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			if !poolDelay(ctx, time.Duration(index)*150*time.Millisecond) {
				return
			}
			backoff := 2 * time.Second
			for ctx.Err() == nil {
				attempt, stop := context.WithCancel(ctx)
				s, err := open(attempt, index)
				if err == nil && s != nil {
					if ctx.Err() != nil {
						stop()
						s.Close()
						return
					}
					lane := &poolLane{session: s}
					p.mu.Lock()
					p.lanes = append(p.lanes, lane)
					p.mu.Unlock()
					p.notify()
					first.Do(func() { close(ready) })
					established := time.Now()
					select {
					case <-ctx.Done():
					case <-s.Done():
					}
					p.mu.Lock()
					for i, entry := range p.lanes {
						if entry == lane {
							p.lanes = append(p.lanes[:i], p.lanes[i+1:]...)
							break
						}
					}
					p.mu.Unlock()
					p.notify()
					stop()
					s.Close()
					if time.Since(established) > time.Minute {
						backoff = 2 * time.Second
					}
				} else {
					stop()
					if s != nil {
						s.Close()
					}
				}
				if !poolDelay(ctx, backoff+time.Duration(rand.Int63n(int64(time.Second)))) {
					return
				}
				backoff *= 2
				if backoff > 30*time.Second {
					backoff = 30 * time.Second
				}
			}
		}(index)
	}
	go func() { workers.Wait(); close(p.done) }()
	timer := time.NewTimer(35 * time.Second)
	defer timer.Stop()
	select {
	case <-ready:
		if ctx.Err() == nil {
			return p, nil
		}
	case <-ctx.Done():
	case <-timer.C:
	}
	p.Close()
	if parent.Err() != nil {
		return nil, parent.Err()
	}
	return nil, errors.New("no authenticated stream pool lane became ready")
}

func poolDelay(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return ctx.Err() == nil
	}
}

func (p *StreamPool) notify() {
	select {
	case p.changes <- struct{}{}:
	default:
	}
}

func (p *StreamPool) Changes() <-chan struct{} { return p.changes }
func (p *StreamPool) Done() <-chan struct{}    { return p.done }
func (p *StreamPool) Close() error             { p.cancel(); <-p.done; return nil }

func (p *StreamPool) LiveCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	count := 0
	for _, lane := range p.lanes {
		select {
		case <-lane.session.Done():
		default:
			count++
		}
	}
	return count
}

func (p *StreamPool) Open(ctx context.Context) (io.ReadWriteCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	var best *poolLane
	bestIndex, total, n := 0, 0, len(p.lanes)
	for i := 0; i < n; i++ {
		index := (p.cursor + i) % n
		lane := p.lanes[index]
		total += lane.active
		select {
		case <-lane.session.Done():
			continue
		default:
		}
		if best == nil || lane.active < best.active {
			best = lane
			bestIndex = index
		}
	}
	if best == nil || total >= 32 {
		p.mu.Unlock()
		return nil, errors.New("no available stream pool capacity")
	}
	best.active++
	p.cursor = (bestIndex + 1) % n
	p.mu.Unlock()
	release := func() { p.mu.Lock(); best.active--; p.mu.Unlock() }
	stream, err := best.session.Open(ctx)
	if err != nil {
		release()
		return nil, err
	}
	return &poolStream{ReadWriteCloser: stream, release: release}, nil
}

type poolStream struct {
	io.ReadWriteCloser
	once    sync.Once
	release func()
}

func (s *poolStream) Close() error {
	err := s.ReadWriteCloser.Close()
	s.once.Do(s.release)
	return err
}
