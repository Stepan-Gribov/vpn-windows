package dnsttclient

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestQueryBudgetIsSharedAcrossLanesAndCancellable(t *testing.T) {
	b := NewQueryBudget(100)
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				if err := b.wait(context.Background()); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if time.Since(start) < 180*time.Millisecond {
		t.Fatal("query rate multiplied by lane count")
	}
	slow := NewQueryBudget(1)
	slow.wait(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start = time.Now()
	if err := slow.wait(ctx); err != context.Canceled {
		t.Fatal(err)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("query pacing delayed cancellation")
	}
}
