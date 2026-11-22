package desktop

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/net/idna"
	"io"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Release builds set these from project.json and the source revision.
var Version = "1.0.0-preview.4"
var Build = "windows-dev"

const BuiltinID = "tndtun.builtin.dns.v1"

type DNS struct {
	Name               string   `json:"name"`
	Domain             string   `json:"domain"`
	PublicKey          string   `json:"publicKey"`
	Resolver           string   `json:"resolver"`
	SessionCount       int      `json:"sessionCount"`
	AutoDetectResolver bool     `json:"autoDetectResolver"`
	SavedResolvers     []string `json:"savedResolvers"`
	UseWiFiResolver    bool     `json:"useWiFiResolver"`
	WiFiResolver       string   `json:"wifiResolver"`
	TunnelType         string   `json:"tunnelType"`
	Username           string   `json:"sshUsername"`
	Password           string   `json:"sshPassword"`
	PrivateKey         string   `json:"sshPrivateKey"`
	HostKey            string   `json:"sshHostKey"`
}
type Profile struct {
	ID           string `json:"id"`
	Mode         string `json:"mode"`
	Title        string `json:"title,omitempty"`
	CallLink     string `json:"callLink"`
	Server       string `json:"server"`
	VlessID      string `json:"vlessID"`
	WrapKey      string `json:"wrapKey"`
	DNS          DNS    `json:"dns"`
	AmneziaKey   string `json:"amneziaKey,omitempty"`
	AmneziaName  string `json:"amneziaName,omitempty"`
	Subscription string `json:"subscriptionID,omitempty"`
	ExpiresAt    *int64 `json:"expiresAt,omitempty"`
}
type Entry struct {
	Address  string   `json:"address"`
	Networks []string `json:"networks"`
	Group    bool     `json:"isNetworkGroup"`
}
type Split struct {
	Mode   string  `json:"mode"`
	Bypass []Entry `json:"bypassEntries"`
	Tunnel []Entry `json:"tunnelEntries"`
}
type Settings struct {
	AmneziaSplitEnabled *bool    `json:"amneziaSplitEnabled,omitempty"`
	FullTunnelMinutes   *int     `json:"fullTunnelMinutes,omitempty"`
	AutoConnectOnLaunch bool     `json:"autoConnectOnLaunch,omitempty"`
	TurnSessionCount    int      `json:"turnSessionCount,omitempty"`
	AutoCaptcha         bool     `json:"autoCaptcha"`
	AutoRecovery        bool     `json:"autoRecovery"`
	Interval            int      `json:"turnCheckInterval"`
	Servers             []string `json:"dnsServers"`
	DNSTunnel           *DNS     `json:"dnsTunnel,omitempty"`
	Split               Split    `json:"splitTunneling"`
	IPv6                bool     `json:"ipv6Enabled"`
	Saved               []string `json:"savedDNSServers"`
}
type State struct {
	AppVersion    string    `json:"appVersion"`
	AppBuild      string    `json:"appBuild"`
	Created       string    `json:"createdAt"`
	SettingsOwner string    `json:"settingsOwner,omitempty"`
	Baseline      *Settings `json:"baselineSettings,omitempty"`
	Format        string    `json:"format"`
	Schema        int       `json:"schemaVersion"`
	Profiles      []Profile `json:"profiles"`
	Mode          string    `json:"mode"`
	Selected      string    `json:"selectedProfileID,omitempty"`
	Settings
	Installation  string         `json:"installationID,omitempty"`
	Subscriptions []Subscription `json:"subscriptions,omitempty"`
}

func UUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
func DefaultState() State {
	return State{AppVersion: Version, AppBuild: Build, Created: time.Now().UTC().Format(time.RFC3339), Format: "TnDtun-backup", Schema: 1, Mode: "amnezia", Profiles: []Profile{}, Installation: UUID(), Settings: Settings{AutoCaptcha: true, AutoRecovery: true, Interval: 30, Servers: []string{"1.1.1.1:53", "1.0.0.1:53"}, Saved: []string{}, Split: Split{Mode: "disabled", Bypass: []Entry{}, Tunnel: []Entry{}}}}
}
func Strict(raw []byte, out any, limit int) error {
	if len(raw) > limit {
		return errors.New("Файл превышает допустимый размер")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return errors.New("Слишком глубокий JSON")
		}
		t, e := d.Token()
		if e != nil {
			return e
		}
		if x, ok := t.(json.Delim); ok {
			switch x {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return e
					}
					s, ok := k.(string)
					if !ok || seen[s] {
						return errors.New("Повторяющееся поле JSON")
					}
					seen[s] = true
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
			case '[':
				for d.More() {
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
			default:
				return errors.New("Некорректный JSON")
			}
			_, e = d.Token()
			return e
		}
		return nil
	}
	if e := walk(0); e != nil {
		return errors.New("Некорректный или неоднозначный JSON")
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("Лишние данные после JSON")
	}
	return json.Unmarshal(raw, out)
}
func Pack(v any) []byte { b, _ := json.Marshal(v); return b }
func clean(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) })
}
func Address(s string) (string, error) {
	s = strings.TrimSpace(s)
	if p, e := netip.ParsePrefix(s); e == nil {
		return p.Masked().String(), nil
	}
	if a, e := netip.ParseAddr(s); e == nil {
		return a.String(), nil
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "*."), ".")
	s, e := idna.Lookup.ToASCII(strings.ToLower(s))
	if e != nil || len(s) > 253 || !strings.Contains(s, ".") || strings.ContainsAny(s, ":/@ \\?") {
		return "", errors.New("Некорректный домен, IP или CIDR")
	}
	for _, p := range strings.Split(s, ".") {
		if len(p) == 0 || len(p) > 63 || p[0] == '-' || p[len(p)-1] == '-' {
			return "", errors.New("Некорректный домен")
		}
		for _, c := range p {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("Некорректный домен")
			}
		}
	}
	return s, nil
}
func Resolver(s string) (string, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "https://") {
		u, e := url.Parse(s)
		if e != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/dns-query" || (u.Host != "dns.google" && u.Host != "cloudflare-dns.com") {
			return "", errors.New("Поддерживаются DoH dns.google и cloudflare-dns.com /dns-query")
		}
		return s, nil
	}
	if a, e := netip.ParseAddr(s); e == nil {
		return net.JoinHostPort(a.String(), "53"), nil
	}
	h, p, e := net.SplitHostPort(s)
	if e != nil {
		return "", errors.New("DNS: укажите IP:порт")
	}
	a, e := netip.ParseAddr(h)
	n, e2 := strconv.Atoi(p)
	if e != nil || e2 != nil || n < 1 || n > 65535 {
		return "", errors.New("Некорректный DNS")
	}
	return net.JoinHostPort(a.String(), p), nil
}
func (s *Split) Validate() error {
	if s.Mode == "" {
		s.Mode = "disabled"
	}
	if s.Mode != "disabled" && s.Mode != "bypassSelected" && s.Mode != "tunnelSelected" {
		return errors.New("Неизвестный режим сплита")
	}
	for _, list := range []*[]Entry{&s.Bypass, &s.Tunnel} {
		if len(*list) > 20000 {
			return errors.New("Не более 20000 записей в списке")
		}
		out := []Entry{}
		seen := map[string]bool{}
		count := 0
		for _, r := range *list {
			var e error
			if r.Group {
				if strings.TrimSpace(r.Address) == "" || !clean(r.Address) || len(r.Address) > 2048 || len(r.Networks) == 0 {
					return errors.New("Некорректная группа сетей")
				}
			} else {
				r.Address, e = Address(r.Address)
				if e != nil {
					return e
				}
			}
			ns := []string{}
			used := map[string]bool{}
			for _, n := range r.Networks {
				n, e = Address(n)
				if e != nil {
					return e
				}
				if _, e = netip.ParsePrefix(n); e != nil {
					if _, e = netip.ParseAddr(n); e != nil {
						return errors.New("Группа содержит не IP/CIDR")
					}
				}
				if !used[n] {
					ns = append(ns, n)
					used[n] = true
				}
			}
			count += len(ns)
			if count > 100000 {
				return errors.New("Не более 100000 сетей в списке")
			}
			r.Networks = ns
			k := string(Pack(r))
			if !seen[k] {
				out = append(out, r)
				seen[k] = true
			}
		}
		*list = out
	}
	return nil
}
func ParseEntries(raw []byte) ([]Entry, error) {
	var v any
	if e := Strict(raw, &v, 5<<20); e != nil {
		return nil, e
	}
	var rows []Entry
	switch x := v.(type) {
	case []any:
		for _, r := range x {
			if s, ok := r.(string); ok {
				rows = append(rows, Entry{Address: s, Networks: []string{}})
			} else {
				var e Entry
				if err := Strict(Pack(r), &e, 5<<20); err != nil {
					return nil, err
				}
				rows = append(rows, e)
			}
		}
	case map[string]any:
		keys := []string{}
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			var ns []string
			if e := json.Unmarshal(Pack(x[k]), &ns); e != nil {
				return nil, e
			}
			_, e := Address(k)
			rows = append(rows, Entry{k, ns, e != nil})
		}
	default:
		return nil, errors.New("Нужен массив записей или JSON домен → сети")
	}
	s := Split{Mode: "disabled", Bypass: rows}
	if e := s.Validate(); e != nil {
		return nil, e
	}
	return s.Bypass, nil
}
func (d *DNS) Validate() error {
	var e error
	d.Domain, e = Address(d.Domain)
	if e != nil {
		return e
	}
	if _, e := netip.ParseAddr(d.Domain); e == nil {
		return errors.New("DNS-туннелю нужен домен")
	}
	b, e := hex.DecodeString(d.PublicKey)
	if e != nil || len(b) != 32 {
		return errors.New("Публичный ключ DNSTT: 64 hex-символа")
	}
	if d.SessionCount == 0 {
		d.SessionCount = 4
	}
	if d.SessionCount != 1 && d.SessionCount != 2 && d.SessionCount != 4 && d.SessionCount != 8 {
		return errors.New("Число DNS-потоков: 1, 2, 4 или 8")
	}
	d.Resolver, e = Resolver(d.Resolver)
	if e != nil {
		return e
	}
	if d.WiFiResolver == "" {
		d.WiFiResolver = "https://dns.google/dns-query"
	}
	d.WiFiResolver, e = Resolver(d.WiFiResolver)
	if e != nil {
		return e
	}
	if d.TunnelType == "" {
		d.TunnelType = "socks5"
	}
	if d.TunnelType != "socks5" && d.TunnelType != "ssh" {
		return errors.New("Выход DNS: socks5 или ssh")
	}
	if d.TunnelType == "ssh" && (d.Username == "" || !strings.HasPrefix(d.HostKey, "SHA256:") || d.Password == "" && d.PrivateKey == "") {
		return errors.New("Укажите SSH-имя, пароль/ключ и SHA256 отпечаток")
	}
	if len(d.SavedResolvers) > 100 {
		return errors.New("Слишком много DNS")
	}
	for i, s := range d.SavedResolvers {
		d.SavedResolvers[i], e = Resolver(s)
		if e != nil {
			return e
		}
	}
	return nil
}
func (p *Profile) Validate() error {
	if p.ID == "" {
		p.ID = UUID()
	}
	if len(p.ID) > 200 || !clean(p.ID) || len(p.Title) > 200 || !clean(p.Title) {
		return errors.New("Некорректное имя/ID")
	}
	switch p.Mode {
	case "amnezia":
		_, _, name, e := Amnezia(p.AmneziaKey, 0)
		if p.Title == "" {
			p.Title = name
		}
		return e
	case "turn":
		u, e := url.Parse(p.CallLink)
		if e != nil || u.Scheme != "https" || (u.Host != "vk.com" && u.Host != "vk.ru") || !strings.HasPrefix(u.Path, "/call/join/") || u.User != nil {
			return errors.New("Нужна ссылка VK https://vk.com/call/join/…")
		}
		h, pt, e := net.SplitHostPort(p.Server)
		if e != nil {
			if ip, e2 := netip.ParseAddr(p.Server); e2 == nil {
				p.Server = net.JoinHostPort(ip.String(), "56010")
			} else if !strings.Contains(p.Server, ":") {
				p.Server = net.JoinHostPort(p.Server, "56010")
			} else {
				return errors.New("Некорректный TURN-сервер")
			}
			h, pt, e = net.SplitHostPort(p.Server)
		}
		n, _ := strconv.Atoi(pt)
		if e != nil || h == "" || strings.ContainsAny(h, "/@?\\ \t\n") || n < 1 || n > 65535 {
			return errors.New("Некорректный сервер")
		}
		if !uuidPattern.MatchString(p.VlessID) {
			return errors.New("Нужен VLESS UUID")
		}
		if p.WrapKey != "" {
			b, e := hex.DecodeString(p.WrapKey)
			if e != nil || len(b) != 32 {
				return errors.New("Wrap key: 64 hex-символа")
			}
		}
	case "dns":
		return p.DNS.Validate()
	default:
		return errors.New("Режим: amnezia, turn или dns")
	}
	return nil
}

var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)

func NormalizeTurnSessionCount(count int) int {
	switch count {
	case 1, 2, 4, 10, 16:
		return count
	default:
		return 10
	}
}

func (s *Settings) Validate() error {
	if s.FullTunnelMinutes != nil && !validFullTunnelMinutes(*s.FullTunnelMinutes) {
		return errors.New("Интервал полного туннеля: 5, 15, 30, 60 минут или до отключения")
	}
	s.TurnSessionCount = NormalizeTurnSessionCount(s.TurnSessionCount)
	if s.Interval < 15 || s.Interval > 300 {
		return errors.New("Интервал TURN: 15–300 секунд")
	}
	if len(s.Servers) == 0 || len(s.Servers) > 100 {
		return errors.New("Нужен хотя бы один DNS")
	}
	for i, n := range s.Servers {
		a, e := Resolver(n)
		if e != nil || strings.HasPrefix(a, "https:") {
			return errors.New("DNS приложения: IP:порт")
		}
		s.Servers[i] = a
	}
	if len(s.Saved) > 1000 {
		return errors.New("Слишком много сохранённых DNS")
	}
	for i, n := range s.Saved {
		a, e := Resolver(n)
		if e != nil {
			return e
		}
		s.Saved[i] = a
	}
	if s.DNSTunnel != nil {
		if e := s.DNSTunnel.Validate(); e != nil {
			return e
		}
	}
	return s.Split.Validate()
}
func (s *State) Validate() error {
	if s.AppVersion == "" {
		s.AppVersion = Version
	}
	if s.AppBuild == "" {
		s.AppBuild = "windows-preview1"
	}
	if s.Created == "" {
		s.Created = time.Now().UTC().Format(time.RFC3339)
	}
	if s.Format != "TnDtun-backup" || s.Schema != 1 || len(s.Profiles) > 1000 {
		return errors.New("Неподдерживаемая резервная копия")
	}
	if e := s.Settings.Validate(); e != nil {
		return e
	}
	seen := map[string]bool{}
	for i := range s.Profiles {
		p := &s.Profiles[i]
		if p.ID == "" || p.ID == BuiltinID || seen[p.ID] {
			return errors.New("Повторяющийся ID профиля")
		}
		if e := p.Validate(); e != nil {
			return e
		}
		seen[p.ID] = true
	}
	if s.Selected != "" && s.Selected != BuiltinID && !seen[s.Selected] {
		s.Selected = ""
	}
	return nil
}
func Unbase64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.StdEncoding, base64.RawStdEncoding} {
		if b, e := enc.DecodeString(s); e == nil {
			return b, nil
		}
	}
	return nil, errors.New("Некорректный base64")
}
func Amnezia(input string, depth int) (map[string]any, map[string]any, string, error) {
	bad := func(e string) (map[string]any, map[string]any, string, error) { return nil, nil, "", errors.New(e) }
	if depth >= 4 || len(input) > 2<<20 {
		return bad("Ключ Amnezia слишком большой или вложенный")
	}
	input = strings.TrimSpace(input)
	if strings.HasPrefix(input, "[Interface]") {
		r, e := parseINI(input)
		return r, nil, "Amnezia", e
	}
	raw := []byte(input)
	if strings.HasPrefix(input, "vpn://") {
		b, e := Unbase64(input[6:])
		if e != nil {
			return bad("Повреждённый vpn:// ключ")
		}
		raw = b
		if len(b) > 6 && b[4] == 0x78 {
			n := binary.BigEndian.Uint32(b[:4])
			if n == 0 || n > 2<<20 {
				return bad("Размер ключа Amnezia недопустим")
			}
			z, e := zlib.NewReader(bytes.NewReader(b[4:]))
			if e != nil {
				return bad("Повреждённый сжатый ключ")
			}
			raw, e = io.ReadAll(io.LimitReader(z, int64(n)+1))
			z.Close()
			if e != nil || len(raw) != int(n) {
				return bad("Повреждённый ключ Amnezia")
			}
		}
	}
	var root map[string]any
	if e := Strict(raw, &root, 2<<20); e != nil {
		return bad("Нужен vpn:// ключ или клиентская конфигурация Amnezia")
	}
	name, _ := root["description"].(string)
	if name == "" {
		name = "Amnezia"
	}
	if k, ok := root["key"].(string); ok {
		return Amnezia(k, depth+1)
	}
	if c, ok := root["containers"].([]any); ok {
		var selected map[string]any
		for _, v := range c {
			m, ok := v.(map[string]any)
			if !ok {
				continue
			}
			if selected == nil || m["container"] == root["defaultContainer"] {
				selected = m
			}
		}
		for _, kind := range []string{"awg", "wireguard", "xray"} {
			section, ok := selected[kind].(map[string]any)
			if !ok {
				continue
			}
			cfg := section["last_config"]
			if t, ok := cfg.(string); ok {
				if strings.HasPrefix(strings.TrimSpace(t), "[Interface]") {
					r, e := parseINI(t)
					return r, nil, name, e
				}
				if e := Strict([]byte(t), &cfg, 2<<20); e != nil {
					return bad("Ключ не содержит клиентской конфигурации")
				}
			}
			m, ok := cfg.(map[string]any)
			if !ok {
				return bad("Административный ключ не поддерживается — экспортируйте подключение")
			}
			if t, ok := m["config"].(string); ok {
				if kind != "xray" {
					r, e := parseINI(t)
					return r, nil, name, e
				}
				if e := Strict([]byte(t), &m, 2<<20); e != nil {
					return bad("Некорректный Xray")
				}
			}
			if kind == "xray" {
				m, e := standaloneXray(m)
				return nil, m, name, e
			}
			return bad("Нет клиентской конфигурации Amnezia")
		}
		return bad("Протокол Amnezia не поддерживается")
	}
	if out, ok := root["outbounds"].([]any); ok && len(out) > 0 {
		m, e := standaloneXray(root)
		return nil, m, name, e
	}
	return bad("Нет клиентской конфигурации")
}
func standaloneXray(root map[string]any) (map[string]any, error) {
	list, _ := root["outbounds"].([]any)
	for _, v := range list {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		switch m["protocol"] {
		case "vless", "vmess", "trojan", "shadowsocks", "wireguard":
			if m["proxySettings"] != nil {
				continue
			}
			m["tag"] = "proxy"
			return map[string]any{"outbounds": []any{m}}, nil
		}
	}
	return nil, errors.New("Нет отдельного поддерживаемого Xray-подключения")
}
func parseINI(s string) (map[string]any, error) {
	f, p := map[string]string{}, map[string]string{}
	var fields map[string]string
	peers := 0
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(strings.SplitN(strings.SplitN(l, "#", 2)[0], ";", 2)[0])
		if l == "" {
			continue
		}
		if strings.HasPrefix(l, "[") {
			switch strings.ToLower(l) {
			case "[interface]":
				fields = f
			case "[peer]":
				peers++
				fields = p
			default:
				return nil, errors.New("Неподдерживаемая секция Amnezia")
			}
			continue
		}
		v := strings.SplitN(l, "=", 2)
		if len(v) != 2 || fields == nil {
			return nil, errors.New("Некорректная INI конфигурация")
		}
		k := strings.ToLower(strings.TrimSpace(v[0]))
		v[1] = strings.TrimSpace(v[1])
		if prev, ok := fields[k]; ok && prev != v[1] {
			return nil, errors.New("Противоречивое поле Amnezia")
		}
		fields[k] = v[1]
	}
	if peers != 1 {
		return nil, errors.New("Нужен ровно один peer")
	}
	key := func(v string) (string, error) {
		b, e := base64.StdEncoding.DecodeString(v)
		if e != nil || len(b) != 32 || bytes.Equal(b, make([]byte, 32)) {
			return "", errors.New("Некорректный ключ WireGuard")
		}
		return hex.EncodeToString(b), nil
	}
	priv, e := key(f["privatekey"])
	if e != nil {
		return nil, e
	}
	pub, e := key(p["publickey"])
	if e != nil {
		return nil, e
	}
	host, port, e := net.SplitHostPort(p["endpoint"])
	n, _ := strconv.Atoi(port)
	if e != nil || host == "" || n < 1 || n > 65535 || !clean(p["endpoint"]) {
		return nil, errors.New("Некорректный endpoint")
	}
	addresses := []string{}
	for _, v := range strings.Split(f["address"], ",") {
		pr, e := netip.ParsePrefix(strings.TrimSpace(v))
		if e != nil {
			return nil, errors.New("Некорректный адрес WireGuard")
		}
		addresses = append(addresses, pr.Addr().String())
	}
	mtu := 1280
	if f["mtu"] != "" {
		mtu, e = strconv.Atoi(f["mtu"])
		if e != nil || mtu < 576 || mtu > 1500 {
			return nil, errors.New("Некорректный MTU")
		}
	}
	uapi := "private_key=" + priv + "\n"
	allowed := map[string]string{}
	for _, k := range strings.Fields("jc jmin jmax s1 s2 s3 s4 h1 h2 h3 h4 i1 i2 i3 i4 i5") {
		allowed[k] = k
	}
	for _, k := range strings.Fields("content_padding_addition rekey_after_time rekey_timeout reject_after_time keepalive_timeout max_handshake_attempts random_trailers disable_cookies") {
		allowed[strings.ReplaceAll(k, "_", "")] = k
	}
	for k, v := range f {
		if m, ok := allowed[k]; ok {
			if !clean(v) {
				return nil, errors.New("Некорректное поле Amnezia")
			}
			if k == "randomtrailers" || k == "disablecookies" {
				switch strings.ToLower(v) {
				case "1", "true", "yes", "on":
					v = "true"
				case "0", "false", "no", "off":
					v = "false"
				default:
					return nil, errors.New("Некорректный переключатель")
				}
			}
			uapi += m + "=" + v + "\n"
		} else {
			switch k {
			case "address", "dns", "privatekey", "mtu", "listenport", "headerprotectionkey":
			default:
				return nil, fmt.Errorf("Неподдерживаемое поле Amnezia: %s", k)
			}
		}
	}
	if f["headerprotectionkey"] != "" {
		h, e := key(f["headerprotectionkey"])
		if e != nil {
			return nil, e
		}
		uapi += "header_protection_key=" + h + "\n"
	}
	uapi += "replace_peers=true\npublic_key=" + pub + "\n"
	if p["presharedkey"] != "" {
		k, e := key(p["presharedkey"])
		if e != nil {
			return nil, e
		}
		uapi += "preshared_key=" + k + "\n"
	}
	keep := p["persistentkeepalive"]
	if keep == "" {
		keep = "25"
	}
	if !regexp.MustCompile(`^[0-9]+(-[0-9]+)?$`).MatchString(keep) {
		return nil, errors.New("Некорректный keepalive")
	}
	uapi += "endpoint=" + p["endpoint"] + "\nreplace_allowed_ips=true\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=" + keep + "\n"
	dns := []string{}
	for _, v := range strings.Split(f["dns"], ",") {
		if a, e := netip.ParseAddr(strings.TrimSpace(v)); e == nil {
			dns = append(dns, a.String())
		}
	}
	if len(dns) == 0 {
		dns = []string{"1.1.1.1"}
	}
	return map[string]any{"addresses": addresses, "dns": dns, "mtu": mtu, "uapi": uapi}, nil
}
