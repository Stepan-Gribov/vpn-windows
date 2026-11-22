package desktop

import (
	"context"
	"errors"
	"time"
)

const amneziaProbeBudget = 15 * time.Second

var amneziaRetryDelays = [...]time.Duration{
	15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute,
}

type amneziaHealth struct {
	path         string
	offlineSince time.Time
	nextProbe    time.Time
	failures     int
}

func (h *amneziaHealth) observe(path string, now time.Time) (changed, offlineTooLong bool) {
	changed = path != h.path
	if changed {
		h.path, h.failures, h.nextProbe = path, 0, now
	}
	if path != "" {
		h.offlineSince = time.Time{}
		return changed, false
	}
	if h.offlineSince.IsZero() {
		h.offlineSince = now
	}
	return changed, now.Sub(h.offlineSince) >= 3*time.Second
}

func (h *amneziaHealth) record(path string, passed bool, now time.Time) bool {
	if path == "" || path != h.path {
		return false
	}
	if passed {
		h.failures = 0
		h.nextProbe = now.Add(30 * time.Second)
	} else {
		h.failures++
		h.nextProbe = now.Add(5 * time.Second)
	}
	return h.failures >= 2
}

type amneziaRecoveryHooks struct {
	current func() bool
	path    func() string
	now     func() time.Time
	wait    func(context.Context, time.Duration) error
	soft    func()
	release func() error
	rebuild func(context.Context) error
	restore func(context.Context) error
	verify  func(context.Context, bool) (int64, error)
	phase   func(string, string)
}

func recoverAmnezia(ctx context.Context, h amneziaRecoveryHooks, packetFailed bool) (int64, error) {
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !h.current() {
			return context.Canceled
		}
		return nil
	}
	verify := func(system bool) (int64, error) {
		probe, cancel := context.WithTimeout(ctx, amneziaProbeBudget)
		defer cancel()
		return h.verify(probe, system)
	}

	if err := check(); err != nil {
		return 0, err
	}
	if original := h.path(); original != "" && !packetFailed {
		h.phase("recovering", "Проверяю соединение Amnezia")
		h.soft()
		latency, err := verify(true)
		if stop := check(); stop != nil {
			return 0, stop
		}
		if err == nil && original == h.path() {
			return latency, nil
		}
	}

	// Release before waiting or rebuilding. Any attempted restoration can
	// have applied routes even if its caller received an error.
	if err := h.release(); err != nil {
		return 0, err
	}
	var retryAt time.Time
	failures := 0
	lastPath := h.path()
	for {
		if err := check(); err != nil {
			return 0, err
		}
		path := h.path()
		if path != lastPath {
			lastPath, failures, retryAt = path, 0, time.Time{}
		}
		if path == "" {
			h.phase("waiting_network", "Жду доступную сеть")
		} else if h.now().Before(retryAt) {
			h.phase("retry_wait", "VPN восстанавливается в фоне. Обычный интернет доступен.")
		} else {
			h.phase("recovering", "Проверяю Amnezia перед восстановлением маршрутов")
			err := h.rebuild(ctx)
			if err == nil {
				_, err = verify(false)
			}
			if stop := check(); stop != nil {
				return 0, errors.Join(stop, h.release())
			}
			if err == nil && path == h.path() {
				h.phase("recovering", "Проверяю восстановленный VPN")
				err = h.restore(ctx)
				if err == nil {
					latency, verified := verify(true)
					if verified == nil && check() == nil && path == h.path() {
						return latency, nil
					}
				}
			}
			if err := h.release(); err != nil {
				return 0, err
			}
			if path == h.path() {
				retryAt = h.now().Add(amneziaRetryDelays[failures])
				failures = min(failures+1, len(amneziaRetryDelays)-1)
			}
			continue
		}
		if err := h.wait(ctx, time.Second); err != nil {
			return 0, err
		}
	}
}

func pauseContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
