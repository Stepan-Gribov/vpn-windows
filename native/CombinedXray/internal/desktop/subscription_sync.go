package desktop

import (
	"encoding/json"
	"errors"
	"time"
)

type SubscriptionSyncPolicy struct {
	Enabled         bool `json:"enabled"`
	IntervalMinutes int  `json:"intervalMinutes"`
}

func decodeSubscriptionSync(raw json.RawMessage) (*SubscriptionSyncPolicy, error) {
	if raw == nil {
		return nil, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	var enabled *bool
	var interval *int
	if len(fields) != 2 || json.Unmarshal(fields["enabled"], &enabled) != nil || enabled == nil ||
		json.Unmarshal(fields["intervalMinutes"], &interval) != nil || interval == nil ||
		*interval < 15 || *interval > 1440 {
		return nil, errors.New("Некорректная политика обновления подписок")
	}
	return &SubscriptionSyncPolicy{Enabled: *enabled, IntervalMinutes: *interval}, nil
}

func (s Subscription) automaticSyncEnabled() bool {
	return s.SyncPolicy != nil && s.SyncPolicy.Enabled &&
		s.SyncPolicy.IntervalMinutes >= 15 && s.SyncPolicy.IntervalMinutes <= 1440 &&
		s.Status == "active" && !s.NeedsActivation
}

func (s Subscription) syncDue(now time.Time) bool {
	return s.automaticSyncEnabled() && s.NextSync > 0 && now.Unix() >= s.NextSync &&
		now.Unix() >= s.RetrySyncAt
}

func (s *Subscription) recordSyncSuccess(now time.Time) {
	s.Sync = now.Unix()
	s.NextSync = 0
	s.RetrySyncAt = 0
	if s.automaticSyncEnabled() {
		s.NextSync = now.Add(time.Duration(s.SyncPolicy.IntervalMinutes) * time.Minute).Unix()
	}
}

func (s *Subscription) postponeFailedSync(now time.Time) {
	if !s.automaticSyncEnabled() {
		return
	}
	s.RetrySyncAt = now.Add(15 * time.Minute).Unix()
}
