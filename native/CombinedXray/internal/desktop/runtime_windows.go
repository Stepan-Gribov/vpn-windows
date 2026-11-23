package desktop

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	"golang.org/x/net/proxy"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	lib "kindlyvpn/native"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"
)

type Network struct {
	Name     string
	RouteKey string
	DNS      []string
	WiFi     bool
	Score    uint32
}

func Physical() (Network, error) {
	as, e := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludeGateways)
	if e != nil {
		return Network{}, e
	}
	ns := []Network{}
	for _, a := range as {
		row, e := a.LUID.Interface()
		if e != nil || row.InterfaceAndOperStatusFlags&winipcfg.IAOSFHardwareInterface == 0 || a.OperStatus != winipcfg.IfOperStatusUp || a.FirstGatewayAddress == nil {
			continue
		}
		n := Network{Name: a.FriendlyName(), WiFi: a.IfType == winipcfg.IfTypeIEEE80211, Score: a.Ipv4Metric, DNS: []string{}}
		var addresses []string
		for local := a.FirstUnicastAddress; local != nil; local = local.Next {
			if ip := local.Address.IP(); ip != nil && ip.IsGlobalUnicast() {
				addresses = append(addresses, ip.String())
			}
		}
		sort.Strings(addresses)
		n.RouteKey = a.FirstGatewayAddress.Address.IP().String() + "/" + strings.Join(addresses, ",")
		for d := a.FirstDNSServerAddress; d != nil; d = d.Next {
			ip := d.Address.IP()
			if ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
				n.DNS = append(n.DNS, net.JoinHostPort(ip.String(), "53"))
			}
		}
		if len(n.DNS) == 0 {
			n.DNS = []string{"1.1.1.1:53"}
		}
		ns = append(ns, n)
	}
	sort.SliceStable(ns, func(i, j int) bool { return ns[i].Score < ns[j].Score })
	if len(ns) == 0 {
		return Network{}, errors.New("Нет активного физического подключения к интернету")
	}
	return ns[0], nil
}
func protect(data []byte, decode bool) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("Пустое хранилище")
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	var e error
	if decode {
		e = windows.CryptUnprotectData(&in, nil, nil, 0, nil, 1, &out)
	} else {
		e = windows.CryptProtectData(&in, nil, nil, 0, nil, 1, &out)
	}
	if e != nil {
		return nil, errors.New("Не удалось открыть защищённые данные этого пользователя")
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte{}, unsafe.Slice(out.Data, out.Size)...), nil
}
func Save(path string, s State) error {
	raw, e := protect(Pack(s), false)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	tmp := path + "." + UUID() + ".tmp"
	defer os.Remove(tmp)
	if e = os.WriteFile(tmp, raw, 0600); e != nil {
		return e
	}
	a, _ := windows.UTF16PtrFromString(tmp)
	b, _ := windows.UTF16PtrFromString(path)
	return windows.MoveFileEx(a, b, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
func Load(path string) (State, error) {
	s := DefaultState()
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return s, Save(path, s)
	}
	if e != nil {
		return s, e
	}
	b, e = protect(b, true)
	if e != nil {
		return s, e
	}
	if e = Strict(b, &s, 24<<20); e != nil {
		return s, e
	}
	if e = s.Validate(); e != nil {
		return s, e
	}
	if s.Installation == "" {
		return s, errors.New("Повреждён идентификатор установки")
	}
	return s, nil
}

type Controller struct {
	connectMu                                        sync.Mutex
	mu                                               sync.Mutex
	writeMu                                          sync.Mutex
	panelMu                                          sync.Mutex
	s                                                State
	path                                             string
	phase                                            string
	active                                           string
	message                                          string
	latency                                          int64
	up, down                                         int64
	upRate, downRate                                 int64
	out                                              io.Writer
	cancel                                           context.CancelFunc
	done                                             chan struct{}
	lifetime                                         context.Context
	panelCancel                                      context.CancelFunc
	requestPanel                                     func(context.Context, Trust, string, any, string) ([]byte, error)
	syncWake                                         chan struct{}
	generation                                       uint64
	activeConfig                                     [32]byte
	reconnectNeeded                                  bool
	full                                             temporaryTunnel
	routingRequests                                  chan routingRequest
	routingSupported, routingPending, routesReleased bool
}

func NewController(out io.Writer) (*Controller, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return nil, errors.New("LOCALAPPDATA недоступен")
	}
	path := filepath.Join(base, "TnDtun", "state.bin")
	if test := os.Getenv("TNDTUN_TEST_DATA"); test != "" {
		path = filepath.Join(test, "state.bin")
	}
	s, e := Load(path)
	if e != nil {
		return nil, e
	}
	return &Controller{s: s, path: path, phase: "disconnected", out: out, lifetime: context.Background(), syncWake: make(chan struct{}, 1), requestPanel: panelRequest}, nil
}
func (c *Controller) send(v any) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	json.NewEncoder(c.out).Encode(v)
}
func (c *Controller) viewLocked() map[string]any {
	profiles := []map[string]any{}
	all := append([]Profile{Builtin()}, c.s.Profiles...)
	for _, p := range all {
		profiles = append(profiles, map[string]any{"id": p.ID, "mode": p.Mode, "title": ProfileName(p), "managed": p.Subscription != "", "expired": p.ExpiresAt != nil && time.Now().Unix() >= *p.ExpiresAt})
	}
	subs := []map[string]any{}
	for _, s := range c.s.Subscriptions {
		subs = append(subs, map[string]any{"id": s.ID, "name": s.Name, "activationCode": s.ActivationCode, "server": s.Trust.API, "status": s.Status, "expiresAt": s.Expiry, "lastSync": s.Sync, "nextSync": s.NextSync, "autoSync": s.automaticSyncEnabled(), "needsActivation": s.NeedsActivation})
	}
	var helper map[string]any
	json.Unmarshal([]byte(lib.KindlyTurnStatus()), &helper)
	var fullUntil int64
	if !c.full.until.IsZero() {
		fullUntil = c.full.until.Unix()
	}
	return map[string]any{"temporaryFullTunnel": c.full.enabled, "fullTunnelUntil": fullUntil, "fullTunnelSupported": c.routingSupported, "routingPending": c.routingPending, "routesReleased": c.routesReleased, "version": Version, "profiles": profiles, "subscriptions": subs, "selected": c.s.Selected, "mode": c.s.Mode, "phase": c.phase, "active": c.active, "message": c.message, "latency": c.latency, "up": c.up, "down": c.down, "upRate": c.upRate, "downRate": c.downRate, "captcha": helper["captcha_required"] == true, "reconnectRecommended": c.reconnectNeeded, "settings": c.s.Settings}
}
func (c *Controller) View() any { c.mu.Lock(); defer c.mu.Unlock(); return c.viewLocked() }
func (c *Controller) event()    { c.send(map[string]any{"event": "state", "data": c.View()}) }
func (c *Controller) phaseSet(phase, msg string) {
	c.mu.Lock()
	c.phase = phase
	c.message = msg
	c.mu.Unlock()
	c.event()
}
func (c *Controller) mutate(fn func(*State) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var s State
	json.Unmarshal(Pack(c.s), &s)
	if e := fn(&s); e != nil {
		return e
	}
	if e := s.Validate(); e != nil {
		return e
	}
	if e := Save(c.path, s); e != nil {
		return e
	}
	c.s = s
	c.checkActiveConfigLocked()
	return nil
}

// Only fields applied at connection time should prompt a reconnect.
func connectionFingerprint(p Profile, settings Settings) [32]byte {
	p.Title, p.ExpiresAt = "", nil
	settings = settings.effectiveRouting(p.Mode, false)
	config := map[string]any{"profile": p, "ipv6": settings.IPv6, "dns": settings.Servers, "split": settings.Split}
	if p.Mode == "turn" {
		config["channels"] = NormalizeTurnSessionCount(settings.TurnSessionCount)
	}
	return sha256.Sum256(Pack(config))
}

func (c *Controller) checkActiveConfigLocked() {
	c.reconnectNeeded = false
	if c.active == "" || c.activeConfig == [32]byte{} {
		return
	}
	if c.active == BuiltinID {
		c.reconnectNeeded = connectionFingerprint(Builtin(), c.s.Settings) != c.activeConfig
		return
	}
	for _, p := range c.s.Profiles {
		if p.ID == c.active && c.allowedLocked(p) {
			c.reconnectNeeded = connectionFingerprint(p, c.s.Settings) != c.activeConfig
			return
		}
	}
}

func (c *Controller) profile(id string) (Profile, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if id == BuiltinID {
		return Builtin(), nil
	}
	for _, p := range c.s.Profiles {
		if p.ID == id {
			if !c.allowedLocked(p) {
				return p, errors.New("Доступ истёк или отозван")
			}
			return p, nil
		}
	}
	return Profile{}, errors.New("Выберите профиль")
}
func (c *Controller) allowedLocked(p Profile) bool {
	if p.Subscription == "" {
		return p.ExpiresAt == nil || time.Now().Unix() < *p.ExpiresAt
	}
	for _, s := range c.s.Subscriptions {
		if s.ID == p.Subscription {
			return s.Status == "active" && (s.Expiry == nil || time.Now().Unix() < *s.Expiry)
		}
	}
	return false
}
func (c *Controller) Stop() error { c.connectMu.Lock(); defer c.connectMu.Unlock(); return c.stop() }
func (c *Controller) stop() error {
	c.mu.Lock()
	cancel, done := c.cancel, c.done
	c.mu.Unlock()
	if cancel == nil {
		return nil
	}
	c.phaseSet("disconnecting", "")
	cancel()
	select {
	case <-done:
		return nil
	case <-time.After(25 * time.Second):
		return errors.New("Остановка занимает больше времени; закройте приложение для завершения процесса")
	}
}
func freePort() (int, error) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return 0, e
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
func helper(p Profile, s Settings, n Network) error {
	if p.Mode == "amnezia" {
		return nil
	}
	var v any
	if p.Mode == "turn" {
		v = map[string]any{"provider": "vk", "vk_link": p.CallLink, "peer_addr": p.Server, "session_count": NormalizeTurnSessionCount(s.TurnSessionCount), "use_udp": true, "listen": "127.0.0.1:9000", "wrap_key": p.WrapKey}
	} else {
		d := p.DNS
		rs := []string{}
		if d.UseWiFiResolver && n.WiFi {
			rs = append(rs, d.WiFiResolver)
		}
		if d.AutoDetectResolver {
			rs = append(rs, n.DNS...)
		}
		rs = append(rs, d.Resolver)
		rs = append(rs, d.SavedResolvers...)
		if len(rs) > 4 {
			rs = rs[:4]
		}
		// The legacy carrier schema requires a literal DNS endpoint; the
		// physical-network carrier uses the complete list, including DoH.
		literal := "1.1.1.1:53"
		for _, r := range rs {
			if !strings.HasPrefix(r, "https:") {
				literal = r
				break
			}
		}
		v = map[string]any{"provider": "managed_dns", "managed_dns": map[string]any{"built_in": d.TunnelType == "socks5", "physical_interface": n.Name, "resolvers": rs, "domain": d.Domain, "public_key": d.PublicKey, "resolver": literal, "session_count": d.SessionCount, "tunnel_type": d.TunnelType, "ssh_username": d.Username, "ssh_password": d.Password, "ssh_private_key": d.PrivateKey, "ssh_host_key": d.HostKey}}
	}
	if lib.KindlyTurnStart(string(Pack(v))) != 0 {
		return errors.New("Не удалось запустить транспорт; проверьте профиль")
	}
	return nil
}
func waitHelper(ctx context.Context, p Profile) error {
	if p.Mode == "amnezia" {
		return nil
	}
	timer := time.NewTimer(300 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	for {
		var v map[string]any
		json.Unmarshal([]byte(lib.KindlyTurnStatus()), &v)
		if v["ready"] == true {
			return nil
		}
		if v["running"] == false && v["last_error"] != "" {
			return errors.New("Не удалось установить транспорт")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return errors.New("Транспорт не готов; проверьте DNS, ссылку VK или CAPTCHA")
		case <-ticker.C:
		}
	}
}
func Probe(ctx context.Context, port int) (int64, error) {
	d, e := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), nil, &net.Dialer{Timeout: 15 * time.Second})
	if e != nil {
		return 0, e
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return 0, errors.New("SOCKS context unavailable")
	}
	t := &http.Transport{Proxy: nil, DialContext: cd.DialContext, DisableKeepAlives: true, TLSHandshakeTimeout: 15 * time.Second}
	defer t.CloseIdleConnections()
	client := &http.Client{Transport: t, Timeout: 25 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://1.1.1.1/cdn-cgi/trace", nil)
	start := time.Now()
	r, e := client.Do(req)
	if e != nil {
		return 0, errors.New("Нет подтверждённого HTTPS через туннель")
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return 0, errors.New("HTTPS-проверка туннеля не прошла")
	}
	_, e = io.Copy(io.Discard, io.LimitReader(r.Body, 65536))
	return time.Since(start).Milliseconds(), e
}
func systemDNS(ctx context.Context) error {
	query := []byte{0x53, 0x41, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'w', 'w', 'w', 7, 'g', 's', 't', 'a', 't', 'i', 'c', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, e := d.DialContext(ctx, "udp4", "198.18.0.2:53")
	if e != nil {
		return e
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(12 * time.Second))
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if _, e = conn.Write(query); e != nil {
		return e
	}
	b := make([]byte, 4096)
	n, e := conn.Read(b)
	if e != nil || n < 12 || b[0] != query[0] || b[1] != query[1] || b[3]&15 != 0 || binary.BigEndian.Uint16(b[6:8]) == 0 {
		return errors.New("DNS-проверка системного туннеля не прошла")
	}
	return nil
}
func (c *Controller) Connect(id string) error {
	c.connectMu.Lock()
	defer c.connectMu.Unlock()
	return c.connect(id)
}

func (c *Controller) reconnectActive() error {
	c.connectMu.Lock()
	defer c.connectMu.Unlock()
	c.mu.Lock()
	id, ready := c.active, c.reconnectNeeded && c.phase == "connected"
	c.mu.Unlock()
	if !ready {
		return nil
	}
	// Check access first, before disconnecting an existing tunnel.
	if _, err := c.profile(id); err != nil {
		return err
	}
	return c.connect(id)
}

func (c *Controller) connectSaved() error {
	c.connectMu.Lock()
	defer c.connectMu.Unlock()
	c.mu.Lock()
	id := c.s.Selected
	start := c.s.AutoConnectOnLaunch && id != "" && c.cancel == nil
	c.mu.Unlock()
	if !start {
		return nil
	}
	return c.connect(id)
}

func (c *Controller) connect(id string) error {
	if e := c.stop(); e != nil {
		return e
	}
	p, e := c.profile(id)
	if e != nil {
		return e
	}
	if e = c.mutate(func(s *State) error { s.Selected = id; s.Mode = p.Mode; return nil }); e != nil {
		return e
	}
	// The running transport must own its configuration, including nested DNS fields.
	var snapshot Profile
	_ = json.Unmarshal(Pack(p), &snapshot)
	p = snapshot
	c.mu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	requests := make(chan routingRequest, 1)
	c.routingRequests = requests
	c.cancel = cancel
	c.done = done
	c.active = id
	c.generation++
	c.phase = "preparing"
	c.message = ""
	c.latency = 0
	c.up = 0
	c.down = 0
	c.upRate, c.downRate = 0, 0
	c.activeConfig, c.reconnectNeeded = [32]byte{}, false
	c.mu.Unlock()
	c.event()
	go func() {
		defer func() {
			_ = lib.DesktopReleaseSystemRoutes(desktopTunnelName)
			lib.StopXray()
			lib.KindlyTurnStop()
			lib.KindlyPhysicalDNSStop()
			c.mu.Lock()
			c.cancel = nil
			c.done = nil
			c.active = ""
			c.phase = "disconnected"
			c.full, c.routingSupported, c.routingPending, c.routesReleased = temporaryTunnel{}, false, false, false
			c.routingRequests = nil
			c.upRate, c.downRate = 0, 0
			c.activeConfig, c.reconnectNeeded = [32]byte{}, false
			c.mu.Unlock()
			close(done)
			c.event()
		}()
		fail := func(e error) {
			if ctx.Err() == nil {
				c.mu.Lock()
				c.message = e.Error()
				c.mu.Unlock()
			}
		}
		n, e := Physical()
		if e != nil {
			fail(e)
			return
		}
		c.mu.Lock()
		var s Settings
		_ = json.Unmarshal(Pack(c.s.Settings), &s)
		c.activeConfig = connectionFingerprint(p, s)
		c.checkActiveConfigLocked()
		c.mu.Unlock()
		sp, e := freePort()
		if e != nil {
			fail(e)
			return
		}
		session := desktopSession{controller: c, profile: p, saved: s, socksPort: sp}
		if e = session.bind(n); e != nil {
			fail(e)
			return
		}
		c.mu.Lock()
		c.routingSupported = s.temporaryTunnelSupported(p.Mode)
		c.mu.Unlock()
		if e = helper(p, s, n); e != nil {
			fail(e)
			return
		}
		c.phaseSet("connecting", "")
		if e = waitHelper(ctx, p); e != nil {
			fail(e)
			return
		}
		if e = session.start(ctx, true, false, false); e != nil {
			fail(errors.New("Не удалось создать VPN. Нужны права администратора и подписанный wintun.dll рядом с приложением"))
			return
		}
		probeCtx, pc := context.WithTimeout(ctx, 75*time.Second)
		ms, e := session.verify(probeCtx, true)
		pc()
		if e != nil {
			fail(e)
			return
		}
		c.mu.Lock()
		c.latency = ms
		c.mu.Unlock()
		c.phaseSet("connected", "")
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		lastProbe := time.Now()
		lastNetwork := time.Now()
		lastSample := time.Now()
		failures := 0
		var rawUp, rawDown int64
		health := amneziaHealth{path: networkIdentity(n), nextProbe: time.Now().Add(30 * time.Second)}
		for {
			select {
			case <-ctx.Done():
				return
			case request := <-requests:
				if ctx.Err() != nil {
					return
				}
				keep, err := session.switchRouting(ctx, request.enabled, false)
				request.result <- err
				if !keep {
					fail(err)
					return
				}
				rawUp, rawDown, lastSample = 0, 0, time.Now()
			case <-tick.C:
				c.mu.Lock()
				valid := false
				for _, r := range c.s.Profiles {
					if r.ID == p.ID {
						valid = c.allowedLocked(r)
					}
				}
				if p.ID == BuiltinID {
					valid = true
				}
				settings := c.s.Settings
				up, down := lib.DesktopStats()
				now := time.Now()
				elapsed := now.Sub(lastSample).Seconds()
				upDelta, downDelta := max(0, up-rawUp), max(0, down-rawDown)
				if elapsed > 0 {
					c.upRate = int64(float64(upDelta) / elapsed)
					c.downRate = int64(float64(downDelta) / elapsed)
				}
				c.up, c.down = c.up+upDelta, c.down+downDelta
				rawUp, rawDown, lastSample = up, down, now
				c.mu.Unlock()
				if !valid {
					fail(errors.New("Доступ истёк, отозван или профиль удалён"))
					return
				}
				if session.full.expired(now) {
					if keep, err := session.switchRouting(ctx, false, true); !keep {
						fail(err)
						return
					}
					rawUp, rawDown, lastSample = 0, 0, time.Now()
				}
				if p.Mode == "amnezia" {
					next, physicalErr := Physical()
					path := networkIdentity(next)
					if physicalErr != nil {
						path = ""
					}
					changed, offline := health.observe(path, now)
					needRepair := offline || lib.DesktopPacketFailed(desktopTunnelName)
					if !needRepair && path != "" && (changed || !now.Before(health.nextProbe)) {
						if changed || networkIdentity(session.network) != path {
							if session.bind(next) == nil {
								lib.AmneziaRefreshSockets()
							}
						}
						check, cancel := context.WithTimeout(ctx, amneziaProbeBudget)
						latency, err := session.verify(check, true)
						cancel()
						observed, observedErr := Physical()
						switch {
						case observedErr != nil || networkIdentity(observed) != path:
							// The next tick must see this as a new path, and rebind.
							health.failures, health.nextProbe = 0, time.Time{}
						default:
							needRepair = health.record(path, err == nil, time.Now())
							if err == nil {
								c.mu.Lock()
								c.latency = latency
								c.mu.Unlock()
							}
						}
					}
					if needRepair {
						if !session.current() {
							fail(errors.New("Профиль Amnezia изменился. Выберите профиль и подключитесь заново."))
							return
						}
						latency, err := session.repair(ctx, lib.DesktopPacketFailed(desktopTunnelName))
						if err != nil {
							fail(errors.New("Восстановление Amnezia остановлено. Подключитесь заново."))
							return
						}
						health = amneziaHealth{path: networkIdentity(session.network), nextProbe: time.Now().Add(30 * time.Second)}
						rawUp, rawDown = lib.DesktopStats()
						lastSample = time.Now()
						c.mu.Lock()
						c.latency = latency
						c.mu.Unlock()
						c.phaseSet("connected", "")
					}
					c.event()
					continue
				}
				if time.Since(lastNetwork) > 5*time.Second {
					lastNetwork = time.Now()
					if next, e := Physical(); e == nil && (next.Name != n.Name || string(Pack(next.DNS)) != string(Pack(n.DNS))) {
						n = next
						lib.DesktopPhysicalNetwork(n.Name, n.DNS)
						lib.KindlyPhysicalDNSStart(n.Name, string(Pack(n.DNS)))
						session.network = n
						if p.Mode == "dns" {
							lib.KindlyTurnStop()
							helper(p, settings, n)
						} else if settings.AutoRecovery {
							lastProbe = time.Time{}
						}
					}
				}
				if p.Mode == "turn" && settings.AutoRecovery && time.Since(lastProbe) >= time.Duration(settings.Interval)*time.Second {
					lastProbe = time.Now()
					probeCtx, cancelProbe := context.WithTimeout(ctx, 25*time.Second)
					ms, e := Probe(probeCtx, sp)
					cancelProbe()
					if e != nil {
						failures++
						c.phaseSet("recovering", fmt.Sprintf("Восстанавливаю VK TURN · попытка %d из 5", failures))
						lib.KindlyTurnStop()
						if e = helper(p, settings, n); e == nil {
							e = waitHelper(ctx, p)
						}
						if e == nil {
							probeCtx, cp := context.WithTimeout(ctx, 30*time.Second)
							ms, e = Probe(probeCtx, sp)
							cp()
						}
						if e != nil && failures >= 5 {
							fail(errors.New("Не удалось восстановить TURN; подключитесь вручную"))
							return
						}
					} else {
						failures = 0
					}
					if e == nil {
						c.mu.Lock()
						c.latency = ms
						c.mu.Unlock()
						c.phaseSet("connected", "")
					}
				}
				c.event()
			}
		}
	}()
	return nil
}
func (c *Controller) beginPanelOperation(parent context.Context) (context.Context, func(), bool) {
	if !c.panelMu.TryLock() {
		return nil, nil, false
	}
	ctx, cancel := context.WithTimeout(parent, 192*time.Second)
	c.mu.Lock()
	c.panelCancel = cancel
	c.mu.Unlock()
	return ctx, func() {
		cancel()
		c.mu.Lock()
		c.panelCancel = nil
		c.mu.Unlock()
		c.panelMu.Unlock()
	}, true
}

func (c *Controller) cancelPanelOperation() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.panelCancel != nil {
		c.panelCancel()
	}
}

type panelResponse struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
	Error  string `json:"error"`
}

func panelResolvers(d DNS, n Network) []string {
	var candidates []string
	if n.WiFi && d.UseWiFiResolver {
		candidates = append(candidates, d.WiFiResolver)
	}
	if d.AutoDetectResolver {
		candidates = append(candidates, n.DNS...)
	}
	candidates = append(candidates, d.Resolver)
	candidates = append(candidates, d.SavedResolvers...)
	candidates = append(candidates, n.DNS...)
	result := make([]string, 0, 4)
	seen := map[string]bool{}
	for _, candidate := range candidates {
		normalized, err := Resolver(candidate)
		if err == nil && !seen[normalized] {
			result = append(result, normalized)
			seen[normalized] = true
		}
		if len(result) == 4 {
			break
		}
	}
	return result
}

func fallbackPanelRoutes(ctx context.Context, origins []Trust, request func(Trust, bool) (panelResponse, error)) (panelResponse, error) {
	for _, origin := range origins {
		if err := ctx.Err(); err != nil {
			return panelResponse{}, err
		}
		reply, err := request(origin, false)
		if err != nil || ctx.Err() != nil {
			return reply, errors.Join(err, ctx.Err())
		}
		if reply.Error == "direct_unavailable" {
			continue
		}
		if len(origins) > 1 && reply.Error == "" && (reply.Status == 502 || reply.Status == 504) {
			body, _ := base64.StdEncoding.DecodeString(reply.Body)
			var serviceError struct {
				Code string `json:"code"`
			}
			if len(body) <= 16<<10 {
				_ = json.Unmarshal(body, &serviceError)
			}
			if serviceError.Code == "" {
				continue
			}
		}
		return reply, nil
	}
	if err := ctx.Err(); err != nil {
		return panelResponse{}, err
	}
	return request(origins[0], true)
}

func panelRequest(ctx context.Context, t Trust, path string, body any, token string) ([]byte, error) {
	n, err := Physical()
	if err != nil {
		return nil, err
	}
	resolvers := panelResolvers(t.DNS, n)
	reply, err := fallbackPanelRoutes(ctx, trustedPanelOrigins(t), func(origin Trust, viaDNS bool) (panelResponse, error) {
		deadline, _ := ctx.Deadline()
		budget := max(1, int(time.Until(deadline).Seconds()))
		id := UUID()
		stop := context.AfterFunc(ctx, func() { lib.KindlyPanelCancel(id) })
		defer stop()
		req := map[string]any{
			"id": id, "api": origin.API, "key_id": origin.KeyID, "public_key": origin.Key,
			"path": path, "body": string(Pack(body)), "token": token,
			"domain": t.DNS.Domain, "dns_key": t.DNS.PublicKey, "sessions": t.DNS.SessionCount,
			"resolvers": resolvers, "interface": n.Name, "physical_dns": n.DNS,
			"budget_seconds": budget, "force_dns": viaDNS, "direct_only": !viaDNS,
		}
		var response panelResponse
		if json.Unmarshal([]byte(lib.KindlyPanelRequest(string(Pack(req)))), &response) != nil {
			return response, errors.New("Неверный ответ транспорта")
		}
		return response, ctx.Err()
	})
	if err != nil {
		return nil, err
	}
	if reply.Status != 200 {
		return nil, PanelError(reply.Status, reply.Error)
	}
	return base64.StdEncoding.DecodeString(reply.Body)
}
func (c *Controller) Activate(input string, confirmed bool) error {
	ctx, finish, ok := c.beginPanelOperation(c.lifetime)
	if !ok {
		return errors.New("Уже выполняется запрос подписки")
	}
	defer finish()
	t, code, e := ParseActivation(input)
	if e != nil {
		return e
	}
	b := Bootstrap()
	if !samePanelService(b, t) && !confirmed {
		return errors.New("Подтвердите новый адрес и ключ сервера")
	}
	c.mu.Lock()
	installation := c.s.Installation
	c.mu.Unlock()
	nonce := Nonce()
	raw, e := c.requestPanel(ctx, t, "activate", map[string]any{"code": code, "installation_id": installation, "platform": "windows", "name": os.Getenv("COMPUTERNAME"), "nonce": nonce}, "")
	if e != nil {
		return e
	}
	var reply struct {
		Device  string          `json:"device_id"`
		Token   string          `json:"token"`
		Package json.RawMessage `json:"package"`
	}
	if Strict(raw, &reply, 12<<20) != nil || len(reply.Token) == 0 || len(reply.Token) > 4096 {
		return errors.New("Неверный ответ активации")
	}
	var prev *Subscription
	c.mu.Lock()
	for _, s := range c.s.Subscriptions {
		if s.Device == reply.Device && samePanelService(t, s.Trust) {
			v := s
			prev = &v
		}
	}
	c.mu.Unlock()
	sub, profiles, settings, e := VerifyPackage(reply.Package, t, nonce, reply.Device, prev)
	if e != nil {
		return e
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if prev != nil {
		sub.ID = prev.ID
		sub.Trust = prev.Trust
		for i := range profiles {
			profiles[i].Subscription = sub.ID
		}
	}
	sub.Token = reply.Token
	if sub.ActivationCode == "" {
		sub.ActivationCode = strings.TrimSpace(input)
		if strings.HasPrefix(strings.ToLower(sub.ActivationCode), "tndtun:") {
			link, _ := url.Parse(sub.ActivationCode)
			sub.ActivationCode = link.Query().Get("code")
		}
	}
	return c.apply(sub, profiles, settings, false)
}
func (c *Controller) apply(sub Subscription, ps []Profile, settings Settings, requireExisting bool) error {
	if settings.DNSTunnel != nil {
		sub.Trust.DNS = *settings.DNSTunnel
	}
	return c.mutate(func(s *State) error {
		index := -1
		for i, old := range s.Subscriptions {
			if old.ID == sub.ID {
				if old.Client != sub.Client || old.Revision > sub.Revision {
					return errors.New("Подписка изменилась")
				}
				index = i
				break
			}
		}
		if requireExisting && index < 0 {
			return errors.New("Подписка уже удалена")
		}
		keep := []Profile{}
		ids := map[string]bool{}
		for _, p := range s.Profiles {
			if p.Subscription != sub.ID {
				keep = append(keep, p)
				ids[p.ID] = true
			}
		}
		for _, p := range ps {
			if ids[p.ID] {
				return errors.New("Конфликт ID профилей")
			}
			keep = append(keep, p)
		}
		s.Profiles = keep
		sub.recordSyncSuccess(time.Now())
		if index < 0 {
			s.Subscriptions = append(s.Subscriptions, sub)
		} else {
			s.Subscriptions[index] = sub
		}
		if s.Baseline == nil {
			b := s.Settings
			s.Baseline = &b
		}
		settings.AutoConnectOnLaunch = s.Settings.AutoConnectOnLaunch
		settings.AmneziaSplitEnabled, settings.FullTunnelMinutes = s.Settings.AmneziaSplitEnabled, s.Settings.FullTunnelMinutes
		settings.TurnSessionCount = s.Settings.TurnSessionCount
		settings.IPv6 = s.Settings.IPv6
		settings.Saved = s.Settings.Saved
		if !requireExisting || s.SettingsOwner == "" || s.SettingsOwner == sub.ID {
			s.SettingsOwner = sub.ID
			s.Settings = settings
		}
		return nil
	})
}
func (c *Controller) syncOne(ctx context.Context, sub Subscription) error {
	nonce := Nonce()
	raw, err := c.requestPanel(ctx, sub.Trust, "sync", map[string]any{"nonce": nonce, "known_revision": sub.Revision}, sub.Token)
	if err != nil {
		return err
	}
	next, profiles, settings, err := VerifyPackage(raw, sub.Trust, nonce, sub.Device, &sub)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	next.Token = sub.Token
	if next.ActivationCode == "" {
		next.ActivationCode = sub.ActivationCode
	}
	return c.apply(next, profiles, settings, true)
}

func (c *Controller) Sync(id string) error { return c.syncSubscriptions(c.lifetime, id, false) }

func (c *Controller) syncSubscriptions(parent context.Context, id string, dueOnly bool) error {
	ctx, finish, ok := c.beginPanelOperation(parent)
	if !ok {
		if dueOnly {
			return nil
		}
		return errors.New("Уже выполняется запрос подписки")
	}
	defer finish()
	c.mu.Lock()
	var subs []Subscription
	now := time.Now()
	for _, sub := range c.s.Subscriptions {
		if (id == "" || id == sub.ID) && (!dueOnly || sub.syncDue(now)) {
			subs = append(subs, sub)
		}
	}
	c.mu.Unlock()
	var firstError error
	for _, sub := range subs {
		if ctx.Err() != nil {
			return errors.Join(firstError, ctx.Err())
		}
		err := c.syncOne(ctx, sub)
		if err == nil {
			c.event()
			continue
		}
		if firstError == nil {
			firstError = err
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			break
		}
		var rejection *PanelHTTPError
		needsActivation := errors.As(err, &rejection) && rejection.Status == 401
		if needsActivation || sub.automaticSyncEnabled() {
			saveErr := c.mutate(func(s *State) error {
				for i := range s.Subscriptions {
					record := &s.Subscriptions[i]
					if record.ID != sub.ID {
						continue
					}
					if needsActivation {
						record.NeedsActivation = true
						record.NextSync = 0
					} else {
						record.postponeFailedSync(time.Now())
					}
					break
				}
				return nil
			})
			if saveErr != nil {
				return errors.Join(firstError, saveErr)
			}
			c.event()
		}
	}
	return firstError
}

func (c *Controller) runSubscriptionScheduler(ctx context.Context) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		_ = c.syncSubscriptions(ctx, "", true)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-c.syncWake:
		}
	}
}
func (c *Controller) Handle(op string, data json.RawMessage) (any, error) {
	var d struct {
		ID        string   `json:"id"`
		Enabled   *bool    `json:"enabled"`
		Text      string   `json:"text"`
		Path      string   `json:"path"`
		Confirmed bool     `json:"confirmed"`
		Profile   Profile  `json:"profile"`
		Settings  Settings `json:"settings"`
	}
	if len(data) > 0 {
		if e := Strict(data, &d, 28<<20); e != nil {
			return nil, e
		}
	}
	switch op {
	case "state":
		return c.View(), nil
	case "connect":
		return nil, c.Connect(d.ID)
	case "connect_saved":
		return nil, c.connectSaved()
	case "reconnect_active":
		return nil, c.reconnectActive()
	case "temporary_full_tunnel":
		if d.Enabled == nil {
			return nil, errors.New("Укажите режим маршрутизации")
		}
		return nil, c.requestTemporaryTunnel(*d.Enabled)
	case "stop":
		return nil, c.Stop()
	case "select":
		p, e := c.profile(d.ID)
		if e != nil {
			return nil, e
		}
		return nil, c.mutate(func(s *State) error { s.Selected = p.ID; s.Mode = p.Mode; return nil })
	case "mode":
		if d.Text != "amnezia" && d.Text != "turn" && d.Text != "dns" {
			return nil, errors.New("Неизвестный режим")
		}
		return nil, c.mutate(func(s *State) error { s.Mode = d.Text; return nil })
	case "profile":
		p, e := c.profile(d.ID)
		return p, e
	case "save_profile":
		if d.Profile.ID == BuiltinID || d.Profile.Subscription != "" {
			return nil, errors.New("Этот профиль управляется приложением или подпиской")
		}
		if e := d.Profile.Validate(); e != nil {
			return nil, e
		}
		return nil, c.mutate(func(s *State) error {
			for i, p := range s.Profiles {
				if p.ID == d.Profile.ID {
					if p.Subscription != "" {
						return errors.New("Редактируется только ручной профиль")
					}
					s.Profiles[i] = d.Profile
					return nil
				}
			}
			s.Profiles = append(s.Profiles, d.Profile)
			s.Selected = d.Profile.ID
			s.Mode = d.Profile.Mode
			return nil
		})
	case "delete_profile":
		if d.ID == BuiltinID {
			return nil, errors.New("Встроенный DNS нельзя удалить")
		}
		return nil, c.mutate(func(s *State) error {
			ps := []Profile{}
			for _, p := range s.Profiles {
				if p.ID == d.ID && p.Subscription != "" {
					return errors.New("Управляйте профилем через подписку")
				}
				if p.ID != d.ID {
					ps = append(ps, p)
				}
			}
			s.Profiles = ps
			return nil
		})
	case "settings":
		return nil, c.mutate(func(s *State) error { s.Settings = d.Settings; return nil })
	case "parse_entries":
		b := []byte(d.Text)
		if d.Path != "" {
			var e error
			b, e = readLimit(d.Path, 5<<20)
			if e != nil {
				return nil, e
			}
		}
		return ParseEntries(b)
	case "import_profile":
		b := []byte(d.Text)
		if d.Path != "" {
			var e error
			b, e = readLimit(d.Path, 2<<20)
			if e != nil {
				return nil, e
			}
		}
		p := Profile{Mode: "amnezia", AmneziaKey: strings.TrimSpace(string(b))}
		if strings.HasPrefix(strings.TrimSpace(string(b)), "{") {
			var candidate Profile
			if Strict(b, &candidate, 2<<20) == nil && candidate.Mode != "" {
				p = candidate
			}
		}
		p.ID = UUID()
		p.Subscription = ""
		p.ExpiresAt = nil
		if e := p.Validate(); e != nil {
			return nil, e
		}
		return p, nil
	case "export":
		c.mu.Lock()
		var s State
		json.Unmarshal(Pack(c.s), &s)
		c.mu.Unlock()
		s.Installation = ""
		s.SettingsOwner = ""
		s.Baseline = nil
		s.Subscriptions = nil
		for i := range s.Profiles {
			s.Profiles[i].Subscription = ""
			s.Profiles[i].ExpiresAt = nil
		}
		b := Pack(s)
		if len(b) > 20<<20 {
			return nil, errors.New("Копия больше 20 МиБ")
		}
		return nil, os.WriteFile(d.Path, b, 0600)
	case "import":
		if !d.Confirmed {
			return nil, errors.New("Подтвердите замену данных")
		}
		b, e := readLimit(d.Path, 20<<20)
		if e != nil {
			return nil, e
		}
		s := DefaultState()
		if e = Strict(b, &s, 20<<20); e != nil {
			return nil, e
		}
		if e = s.Validate(); e != nil {
			return nil, e
		}
		c.panelMu.Lock()
		defer c.panelMu.Unlock()
		c.connectMu.Lock()
		defer c.connectMu.Unlock()
		if e = c.stop(); e != nil {
			return nil, e
		}
		return nil, c.mutate(func(old *State) error {
			s.Installation = old.Installation
			s.AutoConnectOnLaunch = old.AutoConnectOnLaunch
			s.Subscriptions = nil
			s.SettingsOwner = ""
			s.Baseline = nil
			for i := range s.Profiles {
				s.Profiles[i].Subscription = ""
				s.Profiles[i].ExpiresAt = nil
			}
			*old = s
			return nil
		})
	case "activate":
		return nil, c.Activate(d.Text, d.Confirmed)
	case "sync":
		return nil, c.Sync(d.ID)
	case "sync_wake":
		select {
		case c.syncWake <- struct{}{}:
		default:
		}
		return nil, nil
	case "remove_subscription":
		c.panelMu.Lock()
		defer c.panelMu.Unlock()
		return nil, c.mutate(func(s *State) error {
			subs := []Subscription{}
			ps := []Profile{}
			for _, v := range s.Subscriptions {
				if v.ID != d.ID {
					subs = append(subs, v)
				}
			}
			for _, p := range s.Profiles {
				if p.Subscription != d.ID {
					ps = append(ps, p)
				}
			}
			s.Subscriptions = subs
			if s.SettingsOwner == d.ID {
				autoConnect, channels := s.AutoConnectOnLaunch, s.TurnSessionCount
				amneziaSplit, fullMinutes := s.AmneziaSplitEnabled, s.FullTunnelMinutes
				if len(subs) > 0 {
					s.SettingsOwner = subs[len(subs)-1].ID
					s.Settings = subs[len(subs)-1].Settings
				} else {
					s.SettingsOwner = ""
					if s.Baseline != nil {
						s.Settings = *s.Baseline
					}
					s.Baseline = nil
				}
				s.AutoConnectOnLaunch, s.TurnSessionCount = autoConnect, channels
				s.AmneziaSplitEnabled, s.FullTunnelMinutes = amneziaSplit, fullMinutes
			}
			s.Profiles = ps
			return nil
		})
	case "cancel":
		c.cancelPanelOperation()
		return nil, nil
	case "qr":
		b, e := readLimit(d.Path, 12<<20)
		if e != nil {
			return nil, e
		}
		config, _, e := image.DecodeConfig(strings.NewReader(string(b)))
		if e != nil || config.Width < 1 || config.Height < 1 || config.Width > 4096 || config.Height > 4096 {
			return nil, errors.New("Изображение должно быть не больше 4096 × 4096")
		}
		img, _, e := image.Decode(strings.NewReader(string(b)))
		if e != nil {
			return nil, errors.New("Выберите PNG/JPEG/GIF с QR-кодом")
		}
		bm, e := gozxing.NewBinaryBitmapFromImage(img)
		if e != nil {
			return nil, e
		}
		r, e := qrcode.NewQRCodeReader().Decode(bm, nil)
		if e != nil {
			return nil, errors.New("QR-код не найден")
		}
		return r.GetText(), nil
	default:
		return nil, errors.New("Неизвестная команда")
	}
}
func readLimit(path string, limit int) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if len(b) > limit {
		return nil, errors.New("Файл слишком большой")
	}
	return b, e
}
func Serve(in io.Reader, out io.Writer) error {
	c, e := NewController(out)
	if e != nil {
		return e
	}
	defer c.Stop()
	lifetime, stopScheduler := context.WithCancel(context.Background())
	defer stopScheduler()
	c.lifetime = lifetime
	c.event()
	schedulerDone := make(chan struct{})
	go func() {
		defer close(schedulerDone)
		c.runSubscriptionScheduler(lifetime)
	}()
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 65536), 32<<20)
	var wg sync.WaitGroup
	for scanner.Scan() {
		var req struct {
			ID   string          `json:"id"`
			Op   string          `json:"op"`
			Data json.RawMessage `json:"data"`
		}
		if Strict(scanner.Bytes(), &req, 32<<20) != nil || req.ID == "" {
			continue
		}
		if req.Op == "quit" {
			c.Stop()
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if recover() != nil {
					c.send(map[string]any{"id": req.ID, "ok": false, "error": "Внутренняя ошибка"})
				}
			}()
			v, e := c.Handle(req.Op, req.Data)
			reply := map[string]any{"id": req.ID, "ok": e == nil, "data": v}
			if e != nil {
				reply["error"] = e.Error()
			}
			c.send(reply)
			c.event()
		}()
	}
	stopScheduler()
	c.cancelPanelOperation()
	c.Stop()
	<-schedulerDone
	wg.Wait()
	return scanner.Err()
}
