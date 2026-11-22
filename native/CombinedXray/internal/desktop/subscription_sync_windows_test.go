package desktop

import (
	"context"
	"encoding/base64"
	"io"
	"testing"
	"time"
)

func TestPanelRoutesKeepServiceDecisionsAndUsePrimaryDNS(t *testing.T) {
	primary := Trust{API: "https://example.invalid/v1"}
	alternate := Trust{API: "https://alternate.example.invalid/v1"}
	origins := []Trust{primary, alternate}
	var visited []string
	reply, err := fallbackPanelRoutes(context.Background(), origins, func(t Trust, dns bool) (panelResponse, error) {
		visited = append(visited, t.API)
		if dns {
			return panelResponse{Status: 200}, nil
		}
		if t.API == primary.API {
			return panelResponse{Error: "direct_unavailable"}, nil
		}
		return panelResponse{Status: 504, Body: base64.StdEncoding.EncodeToString([]byte("gateway"))}, nil
	})
	if err != nil || reply.Status != 200 || len(visited) != 3 || visited[2] != primary.API {
		t.Fatalf("fallback sequence: %v, %v, %v", visited, reply, err)
	}
	attempts := 0
	reply, err = fallbackPanelRoutes(context.Background(), origins, func(Trust, bool) (panelResponse, error) {
		attempts++
		return panelResponse{Status: 401}, nil
	})
	if err != nil || reply.Status != 401 || attempts != 1 {
		t.Fatal("service rejection must stop fallback")
	}
}

func TestSubscriptionApplyPersistsScheduleAndOperationIsExclusive(t *testing.T) {
	t.Setenv("TNDTUN_TEST_DATA", t.TempDir())
	c, err := NewController(io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	ctx, finish, ok := c.beginPanelOperation(context.Background())
	if !ok {
		t.Fatal("first operation refused")
	}
	if _, _, ok := c.beginPanelOperation(context.Background()); ok {
		t.Fatal("parallel subscription request allowed")
	}
	c.cancelPanelOperation()
	if ctx.Err() != context.Canceled {
		t.Fatal("request was not cancelled")
	}
	finish()
	sub := Subscription{ID: "fixture", Client: UUID(), Status: "active", SyncPolicy: &SubscriptionSyncPolicy{Enabled: true, IntervalMinutes: 15}}
	if err := c.apply(sub, nil, DefaultState().Settings, false); err != nil {
		t.Fatal(err)
	}
	state, err := Load(c.path)
	if err != nil || len(state.Subscriptions) != 1 {
		t.Fatalf("failed to reload DPAPI state: %v", err)
	}
	got := state.Subscriptions[0]
	if got.Sync == 0 || got.NextSync-got.Sync != int64((15*time.Minute)/time.Second) {
		t.Fatalf("persisted timestamp/schedule mismatch: %d/%d", got.Sync, got.NextSync)
	}
	sub.SyncPolicy = nil
	if err := c.apply(sub, nil, DefaultState().Settings, true); err != nil || c.s.Subscriptions[0].NextSync != 0 {
		t.Fatal("legacy packet must remain manually refreshable")
	}
}
