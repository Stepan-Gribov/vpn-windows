package desktop

import (
	"bytes"
	"context"
	"errors"
	"time"

	lib "kindlyvpn/native"
)

const desktopTunnelName = "TnDtun"

type routingRequest struct {
	enabled bool
	result  chan error
}

type desktopSession struct {
	controller *Controller
	profile    Profile
	saved      Settings
	network    Network
	dnsPort    int
	socksPort  int
	full       temporaryTunnel
}

func networkIdentity(n Network) string {
	if n.Name == "" {
		return ""
	}
	return n.Name + "\x00" + n.RouteKey + "\x00" + string(Pack(n.DNS))
}

func (s *desktopSession) current() bool {
	c := s.controller
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active != s.profile.ID || c.s.Selected != s.profile.ID || c.s.Mode != s.profile.Mode {
		return false
	}
	before := s.profile
	before.Title, before.ExpiresAt = "", nil
	for _, profile := range c.s.Profiles {
		if profile.ID == before.ID && c.allowedLocked(profile) {
			profile.Title, profile.ExpiresAt = "", nil
			return bytes.Equal(Pack(before), Pack(profile))
		}
	}
	return false
}

func (s *desktopSession) bind(n Network) error {
	if err := lib.DesktopPhysicalNetwork(n.Name, n.DNS); err != nil {
		return err
	}
	port := int(lib.KindlyPhysicalDNSStart(n.Name, string(Pack(n.DNS))))
	if port == 0 {
		return errors.New("Не удалось открыть прямой DNS")
	}
	s.network, s.dnsPort = n, port
	return nil
}

func (s *desktopSession) start(ctx context.Context, system, replace, full bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	settings := s.saved.effectiveRouting(s.profile.Mode, full)
	config, err := BuildConfig(s.profile, settings, s.network.Name, s.dnsPort, s.socksPort, system)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	lib.SetIPv6Enabled(settings.IPv6)
	if replace {
		return lib.DesktopReconfigure(string(Pack(config)))
	}
	return lib.DesktopStart(string(Pack(config)))
}

func (s *desktopSession) verify(ctx context.Context, system bool) (int64, error) {
	latency, err := Probe(ctx, s.socksPort)
	if err == nil && system {
		err = systemDNS(ctx)
	}
	return latency, err
}

func (s *desktopSession) release() error {
	err := lib.DesktopReleaseSystemRoutes(desktopTunnelName)
	lib.StopXray()
	lib.KindlyPhysicalDNSStop()
	s.dnsPort = 0
	if err != nil {
		return errors.New("Не удалось освободить маршруты Amnezia. Туннель остановлен.")
	}
	return nil
}

func (c *Controller) updateTunnelState(s temporaryTunnel, pending, released bool) {
	c.mu.Lock()
	c.full, c.routingPending, c.routesReleased = s, pending, released
	c.mu.Unlock()
	c.event()
}

func (c *Controller) phaseChanged(phase, message string) {
	c.mu.Lock()
	changed := c.phase != phase || c.message != message
	c.phase, c.message = phase, message
	c.mu.Unlock()
	if changed {
		c.event()
	}
}

func (s *desktopSession) repair(ctx context.Context, packetFailed bool) (int64, error) {
	c := s.controller
	return recoverAmnezia(ctx, amneziaRecoveryHooks{
		current: s.current, now: time.Now, wait: pauseContext,
		path: func() string {
			n, err := Physical()
			if err != nil {
				return ""
			}
			return networkIdentity(n)
		},
		soft: func() { lib.AmneziaRefreshSockets() },
		release: func() error {
			if err := s.release(); err != nil {
				return err
			}
			c.updateTunnelState(s.full, false, true)
			return nil
		},
		rebuild: func(attempt context.Context) error {
			if s.full.expired(time.Now()) {
				s.full = temporaryTunnel{}
				c.updateTunnelState(s.full, false, true)
			}
			n, err := Physical()
			if err != nil {
				return err
			}
			if err = s.bind(n); err != nil {
				return err
			}
			return s.start(attempt, false, false, s.full.enabled)
		},
		restore: func(attempt context.Context) error {
			if s.full.expired(time.Now()) {
				s.full = temporaryTunnel{}
			}
			if err := s.start(attempt, true, true, s.full.enabled); err != nil {
				return err
			}
			c.updateTunnelState(s.full, false, false)
			return nil
		},
		verify: s.verify,
		phase:  c.phaseChanged,
	}, packetFailed)
}

func (s *desktopSession) switchRouting(ctx context.Context, enabled, expired bool) (recoverable bool, err error) {
	c := s.controller
	if s.full.enabled == enabled {
		c.updateTunnelState(s.full, false, false)
		return true, nil
	}
	old := s.full
	c.updateTunnelState(old, true, false)
	c.phaseSet("switching_routes", "Применяю маршрутизацию")
	tryRouting := func(full bool) error {
		if err := s.start(ctx, true, true, full); err != nil {
			return err
		}
		probe, cancel := context.WithTimeout(ctx, amneziaProbeBudget)
		defer cancel()
		latency, err := s.verify(probe, true)
		if err == nil {
			c.mu.Lock()
			c.latency = latency
			c.mu.Unlock()
		}
		return err
	}
	if err = tryRouting(enabled); err == nil {
		s.full = newTemporaryTunnel(enabled, s.saved.fullTunnelDuration(), time.Now())
		c.updateTunnelState(s.full, false, false)
		c.phaseSet("connected", "")
		return true, nil
	}
	// A failed manual change may roll back. An expired override must not
	// silently become permanent when switching back failed.
	if !expired && ctx.Err() == nil && tryRouting(old.enabled) == nil {
		c.updateTunnelState(old, false, false)
		c.phaseSet("connected", "Сохранён прежний режим маршрутизации")
		return true, errors.New("Не удалось применить маршрутизацию")
	}
	_ = lib.DesktopReleaseSystemRoutes(desktopTunnelName)
	return false, errors.New("Не удалось применить маршрутизацию. Подключитесь заново.")
}

func (c *Controller) requestTemporaryTunnel(enabled bool) error {
	c.mu.Lock()
	if c.phase != "connected" || !c.routingSupported || c.routingPending {
		c.mu.Unlock()
		return errors.New("Переключение маршрутов сейчас недоступно")
	}
	requests, done := c.routingRequests, c.done
	result := make(chan error, 1)
	c.routingPending = true
	select {
	case requests <- routingRequest{enabled: enabled, result: result}:
	default:
		c.routingPending = false
		c.mu.Unlock()
		return errors.New("Переключение маршрутов уже выполняется")
	}
	c.mu.Unlock()
	select {
	case err := <-result:
		return err
	case <-done:
		return errors.New("Подключение завершено")
	}
}
