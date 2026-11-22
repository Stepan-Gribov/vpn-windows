package desktop

import "time"

const defaultFullTunnelMinutes = 15

func validFullTunnelMinutes(minutes int) bool {
	switch minutes {
	case 0, 5, 15, 30, 60:
		return true
	default:
		return false
	}
}

func (s Settings) fullTunnelDuration() time.Duration {
	if s.FullTunnelMinutes != nil && validFullTunnelMinutes(*s.FullTunnelMinutes) {
		return time.Duration(*s.FullTunnelMinutes) * time.Minute
	}
	return defaultFullTunnelMinutes * time.Minute
}

func (s Settings) temporaryTunnelSupported(mode string) bool {
	// Older Windows settings applied the split policy to Amnezia implicitly.
	return mode == "turn" || mode == "amnezia" && (s.AmneziaSplitEnabled == nil || *s.AmneziaSplitEnabled)
}

func (s Settings) effectiveRouting(mode string, full bool) Settings {
	if full || !s.temporaryTunnelSupported(mode) {
		s.Split.Mode = "disabled"
	}
	return s
}

type temporaryTunnel struct {
	enabled bool
	until   time.Time
}

func (t temporaryTunnel) expired(now time.Time) bool {
	return t.enabled && !t.until.IsZero() && !now.UTC().Before(t.until)
}

func newTemporaryTunnel(enabled bool, duration time.Duration, now time.Time) temporaryTunnel {
	var t temporaryTunnel
	t.enabled = enabled
	if enabled && duration > 0 {
		// Use wall time so a Windows resume also checks time spent asleep.
		t.until = now.UTC().Add(duration)
	}
	return t
}
