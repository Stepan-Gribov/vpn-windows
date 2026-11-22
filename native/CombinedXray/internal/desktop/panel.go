package desktop

import (
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

//go:embed bootstrap.json
var bootstrapBytes []byte

type Trust struct {
	API   string `json:"api_base"`
	KeyID string `json:"key_id"`
	Key   string `json:"public_key"`
	DNS   DNS    `json:"dns_transport"`
}
type Subscription struct {
	SyncPolicy      *SubscriptionSyncPolicy `json:"subscriptionSync,omitempty"`
	NextSync        int64                   `json:"nextSync,omitempty"`
	RetrySyncAt     int64                   `json:"retrySyncAt,omitempty"`
	ActivationCode  string                  `json:"activationCode,omitempty"`
	ID              string                  `json:"id"`
	Trust           Trust                   `json:"trust"`
	Token           string                  `json:"token"`
	Device          string                  `json:"deviceID"`
	Client          string                  `json:"clientID"`
	Name            string                  `json:"name"`
	Revision        int64                   `json:"revision"`
	Expiry          *int64                  `json:"expiresAt"`
	Status          string                  `json:"status"`
	Sync            int64                   `json:"lastSync"`
	NeedsActivation bool                    `json:"needsActivation"`
	Settings        Settings                `json:"settings"`
}

func Bootstrap() Trust {
	var t Trust
	json.Unmarshal(bootstrapBytes, &t)
	t.DNS.TunnelType = "socks5"
	t.DNS.WiFiResolver = "https://dns.google/dns-query"
	t.DNS.UseWiFiResolver = true
	return t
}

// Only bundled origins pinned to the same signing identity share credentials.
func trustedPanelOrigins(t Trust) []Trust {
	var config struct {
		Trust
		Alternates []string `json:"alternate_api_bases"`
	}
	if json.Unmarshal(bootstrapBytes, &config) != nil || config.KeyID != t.KeyID || config.Key != t.Key {
		return []Trust{t}
	}
	apis := append([]string{config.API}, config.Alternates...)
	if len(apis) > 5 {
		return []Trust{t}
	}
	seen := map[string]bool{}
	var origins []Trust
	for _, api := range apis {
		u, err := url.Parse(api)
		if err != nil || !strings.HasPrefix(api, "https://") || u.Hostname() == "" ||
			u.User != nil || u.Path != "/v1" || u.RawPath != "" || u.RawQuery != "" ||
			u.ForceQuery || u.Fragment != "" || seen[api] {
			return []Trust{t}
		}
		seen[api] = true
		origin := t
		origin.API = api
		origins = append(origins, origin)
	}
	if !seen[t.API] {
		return []Trust{t}
	}
	return origins
}

func samePanelService(a, b Trust) bool {
	for _, origin := range trustedPanelOrigins(a) {
		if origin.API == b.API && origin.Key == b.Key && origin.KeyID == b.KeyID {
			return true
		}
	}
	return false
}

func Builtin() Profile {
	d := Bootstrap().DNS
	d.Name = "Встроенный DNS"
	return Profile{ID: BuiltinID, Mode: "dns", Title: "Встроенный DNS", DNS: d}
}
func Nonce() string {
	b := make([]byte, 24)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func ParseActivation(input string) (Trust, string, error) {
	t := Bootstrap()
	if len(input) > 8192 {
		return t, "", errors.New("Ссылка слишком длинная")
	}
	input = strings.TrimSpace(input)
	code := input
	if strings.HasPrefix(strings.ToLower(input), "tndtun:") {
		u, e := url.Parse(input)
		if e != nil || u.Scheme != "tndtun" || u.Host != "activate" || u.User != nil || u.Path != "" || u.Fragment != "" {
			return t, "", errors.New("Некорректная ссылка активации")
		}
		v, e := url.ParseQuery(u.RawQuery)
		if e != nil || len(v) != 4 {
			return t, "", errors.New("Некорректные поля ссылки")
		}
		for _, k := range []string{"api", "code", "key", "kid"} {
			if len(v[k]) != 1 {
				return t, "", errors.New("Неполная или неоднозначная ссылка")
			}
		}
		t.API, t.Key, t.KeyID = v.Get("api"), v.Get("key"), v.Get("kid")
		code = v.Get("code")
	}
	u, e := url.Parse(t.API)
	key, e2 := base64.RawURLEncoding.DecodeString(t.Key)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" || strings.TrimRight(u.Path, "/") != "/v1" || e2 != nil || len(key) != 32 || !regexp.MustCompile(`^[a-f0-9]{16}$`).MatchString(t.KeyID) {
		return t, "", errors.New("Неподдерживаемый сервер или ключ подписи")
	}
	t.API = strings.TrimRight(t.API, "/")
	code, e = normalizeSubscriptionCode(code)
	return t, code, e
}

func normalizeSubscriptionCode(code string) (string, error) {
	code = strings.ToUpper(strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' || r == '\r' || r == '\n' || r == '\t' {
			return -1
		}
		return r
	}, code))
	if !regexp.MustCompile(`^([A-Z]{4}|[A-Z2-7]{26})$`).MatchString(code) {
		return "", errors.New("Введите 4 английские буквы либо прежний код из 26 символов")
	}
	return code, nil
}
func VerifyPackage(envelope []byte, t Trust, nonce, device string, previous *Subscription) (Subscription, []Profile, Settings, error) {
	bad := func(s string) (Subscription, []Profile, Settings, error) {
		return Subscription{}, nil, Settings{}, errors.New(s)
	}
	var outer struct {
		Algorithm string `json:"algorithm"`
		KeyID     string `json:"key_id"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if Strict(envelope, &outer, 12<<20) != nil || outer.Algorithm != "Ed25519" || outer.KeyID != t.KeyID {
		return bad("Неподтверждённый ключ сервера")
	}
	payload, e := base64.RawURLEncoding.DecodeString(outer.Payload)
	sig, e2 := base64.RawURLEncoding.DecodeString(outer.Signature)
	key, e3 := base64.RawURLEncoding.DecodeString(t.Key)
	if e != nil || e2 != nil || e3 != nil || len(payload) > 8<<20 || len(key) != 32 || len(sig) != 64 || !ed25519.Verify(key, payload, sig) {
		return bad("Подпись пакета неверна; сохранённые данные не изменены")
	}
	var p struct {
		Format   string `json:"format"`
		Schema   int    `json:"schema_version"`
		Nonce    string `json:"nonce"`
		Device   string `json:"device_id"`
		Client   string `json:"client_id"`
		Name     string `json:"client_name"`
		Revision int64  `json:"revision"`
		Status   string `json:"status"`
		Expiry   *int64 `json:"expires_at"`
		Issued   string `json:"issued_at"`
		After    int    `json:"sync_after_seconds"`
		Profiles []struct {
			Profile
			Generation int64  `json:"generation"`
			Title      string `json:"title"`
			Inbound    string `json:"inbound_id"`
			Node       string `json:"node_id"`
		} `json:"profiles"`
		Settings json.RawMessage `json:"settings"`
		Code     *string         `json:"subscription_code"`
	}
	if Strict(payload, &p, 8<<20) != nil || p.Format != "TnDtun-package" || p.Schema != 1 || p.Nonce != nonce || p.Device != device || !uuidPattern.MatchString(device) || !uuidPattern.MatchString(p.Client) || p.Revision < 0 || p.After < 1 || p.After > 86400 || len(p.Profiles) > 1000 || p.Expiry != nil && *p.Expiry < 0 {
		return bad("Неверный или чужой пакет")
	}
	if _, e := time.Parse(time.RFC3339Nano, p.Issued); e != nil {
		return bad("Неверная дата пакета")
	}
	if previous != nil && (p.Client != previous.Client || p.Revision < previous.Revision) {
		return bad("Пакет устарел или принадлежит другому клиенту")
	}
	if p.Status != "active" && p.Status != "revoked" || p.Status == "revoked" && len(p.Profiles) > 0 {
		return bad("Некорректный статус доступа")
	}
	settings := DefaultState().Settings
	var policy *SubscriptionSyncPolicy
	if p.Status == "active" {
		var fields map[string]json.RawMessage
		settings = Settings{}
		if json.Unmarshal(p.Settings, &fields) != nil || fields == nil || json.Unmarshal(p.Settings, &settings) != nil {
			return bad("Отсутствуют или повреждены настройки подписки")
		}
		var err error
		policy, err = decodeSubscriptionSync(fields["subscriptionSync"])
		if err != nil {
			return bad(err.Error())
		}
		if e := settings.Validate(); e != nil {
			return bad("Некорректные настройки подписки")
		}
	} else if previous != nil {
		settings = previous.Settings
	}
	sub := Subscription{ID: t.API + "#" + device, Trust: t, Device: device, Client: p.Client, Name: p.Name, Revision: p.Revision, Status: p.Status, Expiry: p.Expiry, SyncPolicy: policy, Settings: settings}
	if p.Code != nil {
		if len(*p.Code) > 128 {
			return bad("Некорректный код в подписанном пакете")
		}
		code, err := normalizeSubscriptionCode(*p.Code)
		if err != nil {
			return bad("Некорректный код в подписанном пакете")
		}
		sub.ActivationCode = code
	}
	profiles := []Profile{}
	seen := map[string]bool{}
	for _, r := range p.Profiles {
		if !uuidPattern.MatchString(r.ID) || seen[r.ID] || r.Generation < 1 || r.Inbound == "" || r.Node == "" || (r.Mode != "turn" && r.Mode != "amnezia") {
			return bad("Неверный назначенный профиль")
		}
		seen[r.ID] = true
		r.Profile.Title = r.Title
		r.Profile.Subscription = sub.ID
		r.Profile.ExpiresAt = p.Expiry
		if e := r.Profile.Validate(); e != nil {
			return bad("Назначенный профиль повреждён")
		}
		profiles = append(profiles, r.Profile)
	}
	return sub, profiles, settings, nil
}

type PanelHTTPError struct {
	Status  int
	Message string
}

func (e *PanelHTTPError) Error() string { return e.Message }
func PanelError(status int, code string) error {
	if status == 401 {
		return &PanelHTTPError{status, "Доступ не подтверждён: активируйте устройство заново"}
	}
	switch status {
	case 403:
		return errors.New("Доступ отключён или срок подписки истёк")
	case 429:
		return errors.New("Слишком много попыток; повторите позже")
	}
	if status != 0 {
		return fmt.Errorf("Сервер вернул HTTP %d", status)
	}
	return fmt.Errorf("Сервер недоступен (%s); проверьте интернет и DNS", code)
}
