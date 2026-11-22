package transports

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

type fakePoolLane struct {
	id   byte
	done chan struct{}
	once sync.Once
}

func (s *fakePoolLane) Done() <-chan struct{} { return s.done }
func (s *fakePoolLane) Close() error          { s.once.Do(func() { close(s.done) }); return nil }
func (s *fakePoolLane) Open(context.Context) (io.ReadWriteCloser, error) {
	return &fakePoolStream{lane: s}, nil
}

type fakePoolStream struct{ lane *fakePoolLane }

func (s *fakePoolStream) Read(p []byte) (int, error) { p[0] = s.lane.id; return 1, nil }
func (s *fakePoolStream) Write(p []byte) (int, error) {
	select {
	case <-s.lane.done:
		return 0, io.ErrClosedPipe
	default:
		return len(p), nil
	}
}
func (s *fakePoolStream) Close() error { return nil }

func waitPoolCount(t *testing.T, p *StreamPool, count int, timeout time.Duration) {
	t.Helper()
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); {
		if p.LiveCount() == count {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("live lanes=%d, want %d", p.LiveCount(), count)
}

func TestStreamPoolBalancesAndRepairsOnlyFailedLane(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var opened [4]int
	var lanes [4]*fakePoolLane
	p, err := OpenStreamPool(ctx, 4, func(ctx context.Context, index int) (PoolSession, error) {
		lane := &fakePoolLane{id: byte(index), done: make(chan struct{})}
		mu.Lock()
		opened[index]++
		lanes[index] = lane
		mu.Unlock()
		return lane, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	waitPoolCount(t, p, 4, 2*time.Second)
	var streams []io.ReadWriteCloser
	var usage [4]int
	for i := 0; i < 8; i++ {
		s, err := p.Open(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var id [1]byte
		s.Read(id[:])
		usage[id[0]]++
		streams = append(streams, s)
	}
	defer func() {
		for _, s := range streams {
			s.Close()
		}
	}()
	if usage != [4]int{2, 2, 2, 2} {
		t.Fatalf("unbalanced lanes: %v", usage)
	}
	mu.Lock()
	failed := lanes[0]
	mu.Unlock()
	failed.Close()
	waitPoolCount(t, p, 3, time.Second)
	for _, s := range streams {
		var id [1]byte
		s.Read(id[:])
		_, err := s.Write([]byte("existing application bytes"))
		if id[0] == 0 && err == nil {
			t.Fatal("failed lane silently replayed bytes")
		}
		if id[0] != 0 && err != nil {
			t.Fatal("surviving lane was interrupted")
		}
	}
	waitPoolCount(t, p, 4, 4*time.Second)
	mu.Lock()
	attempts := opened
	mu.Unlock()
	if attempts != [4]int{2, 1, 1, 1} {
		t.Fatalf("healthy lanes reconnected: %v", attempts)
	}
	start := time.Now()
	p.Close()
	if time.Since(start) > time.Second {
		t.Fatal("shutdown blocked")
	}
}

func TestStreamPoolCancelsUnauthenticatedLanesAndDoesNotReportReady(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	p, err := OpenStreamPool(ctx, 4, func(attempt context.Context, _ int) (PoolSession, error) {
		<-attempt.Done()
		return nil, attempt.Err()
	})
	if p != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("p=%v err=%v", p, err)
	}
}

func TestStreamPoolFailedLaneDoesNotBlockOthersAndBoundsActiveStreams(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := OpenStreamPool(ctx, 2, func(attempt context.Context, index int) (PoolSession, error) {
		if index == 0 {
			<-attempt.Done()
			return nil, attempt.Err()
		}
		return &fakePoolLane{id: 1, done: make(chan struct{})}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var streams []io.ReadWriteCloser
	defer func() {
		for _, s := range streams {
			s.Close()
		}
	}()
	for i := 0; i < 32; i++ {
		s, err := p.Open(ctx)
		if err != nil {
			t.Fatal(err)
		}
		streams = append(streams, s)
	}
	if extra, err := p.Open(ctx); err == nil {
		extra.Close()
		t.Fatal("unbounded stream buffers")
	}
	streams[0].Close()
	streams[0].Close()
	s, err := p.Open(ctx)
	if err != nil {
		t.Fatal("stream slot not released")
	}
	defer s.Close()
	if extra, err := p.Open(ctx); err == nil {
		extra.Close()
		t.Fatal("double close released a slot twice")
	}
}
