// Package transports carries the existing authenticated KindlyVPN connection
// through alternate first hops. It never decides subscription entitlement.
package transports

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const MaxConfigBytes = 64 * 1024

type Config struct {
	Version      int       `json:"version"`
	StartAfter   string    `json:"start_after,omitempty"`
	Listen       string    `json:"listen,omitempty"`
	BootstrapDNS []string  `json:"bootstrap_dns,omitempty"`
	Profiles     []Profile `json:"profiles"`
}

type Profile struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	DNS        *DNSConfig        `json:"dns,omitempty"`
	HTTPS      *HTTPSConfig      `json:"https,omitempty"`
	Conference *ConferenceConfig `json:"conference,omitempty"`
}

type DNSConfig struct {
	SessionCount int      `json:"session_count,omitempty"`
	MaxQPS       int      `json:"max_qps,omitempty"`
	Domain       string   `json:"domain"`
	PublicKey    string   `json:"public_key"`
	Resolvers    []string `json:"resolvers,omitempty"`
}

type HTTPSConfig struct {
	URL       string `json:"url"`
	PublicKey string `json:"public_key"`
}

type ConferenceConfig struct {
	Provider string `json:"provider"`
	Room     string `json:"room"`
	Key      string `json:"key"`
	Channel  string `json:"channel"`
	Target   string `json:"target"`
}

var safeID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,40}$`)
var domainName = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\.?$`)

func ParseConfig(raw []byte) (Config, error) {
	var cfg Config
	if len(raw) > MaxConfigBytes {
		return cfg, errors.New("configuration exceeds 64 KiB")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&cfg); err != nil {
		return cfg, errors.New("invalid recovery configuration JSON")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return cfg, errors.New("extra configuration data")
	}
	return cfg, cfg.Validate()
}

func (c *Config) Validate() error {
	if c.Version != 1 {
		return errors.New("unsupported recovery configuration version")
	}
	if c.StartAfter != "" && !safeID.MatchString(c.StartAfter) {
		return errors.New("invalid previous route ID")
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:9000"
	}
	if err := loopbackAddress(c.Listen, true); err != nil {
		return errors.New("listener must be a literal loopback address and port")
	}
	if len(c.Profiles) < 1 || len(c.Profiles) > 8 {
		return errors.New("configure between 1 and 8 routes")
	}
	if err := validateResolvers(c.BootstrapDNS); err != nil {
		return err
	}
	seen := make(map[string]bool)
	for _, p := range c.Profiles {
		if !safeID.MatchString(p.ID) || seen[p.ID] {
			return errors.New("route IDs must be unique and use 1–40 letters, digits, underscores or hyphens")
		}
		seen[p.ID] = true
		count := 0
		if p.DNS != nil {
			count++
		}
		if p.HTTPS != nil {
			count++
		}
		if p.Conference != nil {
			count++
		}
		if count != 1 {
			return errors.New("each route requires exactly one transport configuration")
		}
		switch p.Type {
		case "dnstt":
			if p.DNS == nil || !domainName.MatchString(p.DNS.Domain) || len(p.DNS.Domain) > 80 || !keyValid(p.DNS.PublicKey) {
				return errors.New("DNS route requires a short delegated domain and a 32-byte public key")
			}
			if p.DNS.SessionCount < 0 || p.DNS.SessionCount > 8 || p.DNS.MaxQPS < 0 || p.DNS.MaxQPS > 1500 {
				return errors.New("invalid DNS pool size or query budget")
			}
			if err := validateResolvers(p.DNS.Resolvers); err != nil {
				return err
			}
		case "https":
			if p.HTTPS == nil || !secureURL(p.HTTPS.URL) || !keyValid(p.HTTPS.PublicKey) {
				return errors.New("HTTPS route requires an HTTPS URL without credentials or fragments and a 32-byte public key")
			}
		case "conference":
			if !ConferenceAvailable {
				return errors.New("conference routes require a separately built conference pilot")
			}
			if p.Conference == nil {
				return errors.New("missing conference configuration")
			}
			if err := p.Conference.validate(); err != nil {
				return err
			}
		default:
			return errors.New("unknown transport type")
		}
	}
	return nil
}

func (c ConferenceConfig) validate() error {
	if !keyValid(c.Key) || !secureURL(c.Room) {
		return errors.New("conference route requires an HTTPS room URL and a 32-byte key")
	}
	if err := loopbackAddress(c.Target, false); err != nil {
		return errors.New("conference target must be the server's literal loopback VLESS inbound")
	}
	if (c.Provider == "jitsi" && c.Channel == "datachannel") || ((c.Provider == "telemost" || c.Provider == "wbstream") && c.Channel == "vp8channel") {
		return nil
	}
	return errors.New("supported conference routes: Jitsi datachannel, Telemost/WB Stream vp8channel")
}

func keyValid(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == 32 && !bytes.Equal(b, make([]byte, 32))
}

func secureURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && len(value) < 4096
}

func loopbackAddress(value string, allowZero bool) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	n, pe := strconv.Atoi(port)
	if err != nil || !ip.IsLoopback() || pe != nil || n > 65535 || n < 0 || (n == 0 && !allowZero) {
		return errors.New("invalid loopback address")
	}
	return nil
}

func validateResolvers(values []string) error {
	if len(values) > 4 {
		return errors.New("at most four DNS resolvers are allowed")
	}
	for _, value := range values {
		addr, err := netip.ParseAddrPort(value)
		if err != nil || addr.Port() == 0 || addr.Addr().IsUnspecified() || addr.Addr().IsMulticast() {
			return errors.New("DNS resolvers must be literal IP:port addresses")
		}
	}
	return nil
}

// ResolverCandidates puts the current underlying network before provisioned
// fallbacks. A VPN interface's DNS must never be supplied as underlying DNS.
func ResolverCandidates(network, configured []string) []string {
	result := make([]string, 0, 4)
	for _, item := range append(append([]string{}, network...), configured...) {
		item = strings.TrimSpace(item)
		if validateResolvers([]string{item}) != nil {
			continue
		}
		found := false
		for _, old := range result {
			if old == item {
				found = true
			}
		}
		if !found {
			result = append(result, item)
		}
		if len(result) == 4 {
			break
		}
	}
	return result
}
