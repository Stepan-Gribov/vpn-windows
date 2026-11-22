package clientcore

import (
	"context"
	"sync"
)

// Cancellation must close the TURN socket while Allocate/handshake is waiting.
// Otherwise an old generation can outlive Stop and overlap the new runtime.
func newConnectionCleanup(ctx context.Context) (func(func()), func()) {
	var mu sync.Mutex
	var closers []func()
	closed := false
	closeAll := func() {
		mu.Lock()
		if closed {
			mu.Unlock()
			return
		}
		closed = true
		pending := closers
		closers = nil
		mu.Unlock()
		for i := len(pending) - 1; i >= 0; i-- {
			pending[i]()
		}
	}
	stop := context.AfterFunc(ctx, closeAll)
	add := func(close func()) {
		mu.Lock()
		if closed {
			mu.Unlock()
			close()
			return
		}
		closers = append(closers, close)
		mu.Unlock()
	}
	return add, func() { stop(); closeAll() }
}
