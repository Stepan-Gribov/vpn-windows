package desktop

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestAmneziaWatchdogCountsOnlyStablePathFailures(t *testing.T) {
	start := time.Unix(100, 0)
	var health amneziaHealth
	health.observe("wifi", start)
	if health.record("wifi", false, start) || health.nextProbe != start.Add(5*time.Second) {
		t.Fatal("first failure must schedule confirmation")
	}
	health.observe("ethernet", start.Add(time.Second))
	if health.record("wifi", false, start.Add(time.Second)) || health.record("ethernet", false, start.Add(2*time.Second)) {
		t.Fatal("a stale probe must not accumulate a failure on a new path")
	}
	if !health.record("ethernet", false, start.Add(7*time.Second)) {
		t.Fatal("two failures on the same path should trigger recovery")
	}
	_, expired := health.observe("", start.Add(9*time.Second))
	if expired {
		t.Fatal("a short handover should not release routes")
	}
	_, expired = health.observe("", start.Add(12*time.Second))
	if !expired {
		t.Fatal("sustained loss should release routes")
	}
}

func TestAmneziaRecoveryReleasesBeforeRebuildAndBeforeBackoff(t *testing.T) {
	now := time.Unix(1000, 0)
	path := "wifi"
	captured := true
	var operations []string
	attempts := 0
	h := amneziaRecoveryHooks{
		current: func() bool { return true }, path: func() string { return path }, now: func() time.Time { return now },
		soft: func() { operations = append(operations, "soft") },
		release: func() error {
			captured = false
			operations = append(operations, "release")
			return nil
		},
		wait: func(_ context.Context, duration time.Duration) error {
			if captured {
				t.Fatal("windows routes still capture traffic during backoff")
			}
			now = now.Add(duration)
			if now.Equal(time.Unix(1001, 0)) {
				path = "ethernet"
			}
			operations = append(operations, "wait")
			return nil
		},
		rebuild: func(context.Context) error {
			if captured {
				t.Fatal("rebuilding a captured tunnel")
			}
			attempts++
			operations = append(operations, "rebuild")
			return nil
		},
		restore: func(context.Context) error {
			captured = true
			operations = append(operations, "restore")
			return nil
		},
		verify: func(_ context.Context, system bool) (int64, error) {
			if captured != system {
				t.Fatal("probe ran with unexpected route ownership")
			}
			if !system {
				operations = append(operations, "preflight")
				return 7, nil
			}
			operations = append(operations, "system")
			if attempts < 2 {
				return 0, errors.New("broken test route")
			}
			return 21, nil
		},
		phase: func(string, string) {},
	}
	latency, err := recoverAmnezia(context.Background(), h, false)
	want := []string{"soft", "system", "release", "rebuild", "preflight", "restore", "system", "release", "wait", "rebuild", "preflight", "restore", "system"}
	if err != nil || latency != 21 || !reflect.DeepEqual(operations, want) {
		t.Fatalf("unexpected recovery: latency %d, %v; operations %v", latency, err, operations)
	}
}

func TestAmneziaFatalPacketFailureAndUserCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	released := false
	h := amneziaRecoveryHooks{
		current: func() bool { return true }, path: func() string { return "" }, now: time.Now,
		soft:    func() { t.Fatal("packet failure must skip soft rebind") },
		release: func() error { released = true; return nil },
		wait: func(context.Context, time.Duration) error {
			if !released {
				t.Fatal("must relinquish routes while offline")
			}
			cancel()
			return ctx.Err()
		},
		rebuild: func(context.Context) error { t.Fatal("offline recovery must not rebuild"); return nil },
		phase:   func(string, string) {},
	}
	if _, err := recoverAmnezia(ctx, h, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected user cancellation, got %v", err)
	}
}

func TestTemporaryRoutingKeepsSavedPolicyAndExpires(t *testing.T) {
	saved := DefaultState().Settings
	saved.Split = Split{Mode: "bypassSelected", Bypass: []Entry{{Address: "example.org"}}}
	if full := saved.effectiveRouting("turn", true); full.Split.Mode != "disabled" || len(full.Split.Bypass) != 1 ||
		saved.effectiveRouting("turn", false).Split.Mode != "bypassSelected" {
		t.Fatal("temporary full routing must leave stored lists intact")
	}
	amnezia := false
	saved.AmneziaSplitEnabled = &amnezia
	if saved.temporaryTunnelSupported("dns") || saved.temporaryTunnelSupported("amnezia") ||
		saved.effectiveRouting("dns", false).Split.Mode != "disabled" {
		t.Fatal("unavailable modes must not apply split routing")
	}
	now := time.Unix(100, 0)
	temporary := newTemporaryTunnel(true, saved.fullTunnelDuration(), now)
	if temporary.expired(now.Add(15*time.Minute-time.Second)) || !temporary.expired(now.Add(15*time.Minute)) {
		t.Fatal("default must expire at 15 minutes")
	}
	zero := 0
	saved.FullTunnelMinutes = &zero
	if newTemporaryTunnel(true, saved.fullTunnelDuration(), now).expired(now.Add(24 * time.Hour)) {
		t.Fatal("until disconnect must not set a deadline")
	}
}
