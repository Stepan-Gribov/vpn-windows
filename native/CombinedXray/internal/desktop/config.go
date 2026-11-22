package desktop

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

func BuildConfig(p Profile, s Settings, physical string, directPort, socksPort int, system bool) (map[string]any, error) {
	if e := p.Validate(); e != nil {
		return nil, e
	}
	if e := s.Validate(); e != nil {
		return nil, e
	}
	var awg, custom map[string]any
	var err error
	proxy := map[string]any{"tag": "proxy", "protocol": "socks", "settings": map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": 9002}}}}
	switch p.Mode {
	case "amnezia":
		awg, custom, _, err = Amnezia(p.AmneziaKey, 0)
		if err != nil {
			return nil, err
		}
		proxy["settings"] = map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": 9004}}}
	case "turn":
		proxy = map[string]any{"tag": "proxy", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": 9000, "users": []any{map[string]any{"id": p.VlessID, "encryption": "none"}}}}}, "streamSettings": map[string]any{"network": "tcp", "security": "none"}}
	case "dns":
		if p.DNS.TunnelType == "ssh" {
			proxy["settings"] = map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": 9002}}}
		}
	}
	out := []any{proxy}
	if custom != nil {
		list, ok := custom["outbounds"].([]any)
		if !ok || len(list) == 0 {
			return nil, fmt.Errorf("Нет Xray outbounds")
		}
		out = []any{}
		for _, v := range list {
			m, ok := v.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("Некорректный Xray outbound")
			}
			if len(out) == 0 {
				m["tag"] = "proxy"
			}
			if m["tag"] == "direct" || m["tag"] == "block" || m["tag"] == "kindly-dns" {
				continue
			}
			out = append(out, m)
		}
	}
	direct := map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{"domainStrategy": "UseIPv4"}}
	if s.IPv6 {
		direct["settings"] = map[string]any{"domainStrategy": "UseIP"}
	}
	out = append(out, direct, map[string]any{"tag": "block", "protocol": "blackhole"}, map[string]any{"tag": "kindly-dns", "protocol": "dns", "settings": map[string]any{"network": "tcp"}})
	in := []any{map[string]any{"tag": "health", "listen": "127.0.0.1", "port": socksPort, "protocol": "socks", "settings": map[string]any{"udp": true, "auth": "noauth"}}}
	if system {
		in = append(in, map[string]any{"tag": "in_proxy", "protocol": "tun", "settings": map[string]any{"name": "TnDtun", "mtu": 1280, "gateway": []string{"198.18.0.1/30", "fdfe:dcba:9876::1/126"}, "dns": []string{"198.18.0.2"}, "autoSystemRoutingTable": []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"}, "autoOutboundsInterface": physical}, "sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true}})
	}
	rules := []any{map[string]any{"type": "field", "inboundTag": []string{"health", "kindly-dns-query"}, "outboundTag": "proxy"}, map[string]any{"type": "field", "inboundTag": []string{"kindly-dns-direct"}, "outboundTag": "direct"}, map[string]any{"type": "field", "inboundTag": []string{"in_proxy"}, "port": "53", "outboundTag": "kindly-dns"}}
	if !s.IPv6 {
		rules = append(rules, map[string]any{"type": "field", "ip": []string{"::/0"}, "outboundTag": "block"})
	}
	// Keep physical LAN and management routes usable without a geoip asset.
	rules = append(rules, map[string]any{"type": "field", "ip": []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "::1/128", "fe80::/10", "fc00::/7"}, "outboundTag": "direct"})
	fallback, selected := "proxy", "direct"
	var entries []Entry
	switch s.Split.Mode {
	case "tunnelSelected":
		fallback, selected = "direct", "proxy"
		entries = s.Split.Tunnel
	case "bypassSelected":
		entries = s.Split.Bypass
	}
	domains, hints, networks := []string{}, []string{}, []string{}
	for _, r := range entries {
		if !r.Group {
			if _, e := netip.ParsePrefix(r.Address); e == nil {
				networks = append(networks, r.Address)
			} else if _, e := netip.ParseAddr(r.Address); e == nil {
				networks = append(networks, r.Address)
			} else {
				domains = append(domains, "domain:"+r.Address)
				hints = append(hints, "domain:"+r.Address)
			}
		}
		networks = append(networks, r.Networks...)
	}
	if len(domains) > 0 {
		rules = append(rules, map[string]any{"type": "field", "domain": domains, "outboundTag": selected})
	}
	if len(networks) > 0 {
		rules = append(rules, map[string]any{"type": "field", "ip": networks, "outboundTag": selected})
	}
	rules = append(rules, map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": fallback})
	local := fmt.Sprintf("tcp+local://127.0.0.1:%d", directPort)
	server := func(tag string, match []string, remote string) map[string]any {
		address := "tcp://" + remote
		if tag == "direct" {
			address = local
		}
		m := map[string]any{"address": address, "tag": "kindly-dns-query"}
		if tag == "direct" {
			m["tag"] = "kindly-dns-direct"
		}
		if len(match) > 0 {
			m["domains"] = match
			m["skipFallback"] = true
		}
		return m
	}
	dnsServers := []any{}
	addServers := func(tag string, match []string) {
		if tag == "direct" {
			dnsServers = append(dnsServers, server(tag, match, ""))
			return
		}
		for _, remote := range s.Servers {
			dnsServers = append(dnsServers, server(tag, match, remote))
		}
	}
	if len(hints) > 0 {
		addServers(selected, hints)
	}
	addServers(fallback, nil)
	if fallback == "direct" {
		addServers("proxy", nil)
	}
	strategy := "UseIPv4"
	if s.IPv6 {
		strategy = "UseIP"
	}
	root := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": in, "outbounds": out, "routing": map[string]any{"domainStrategy": "AsIs", "rules": rules}, "dns": map[string]any{"queryStrategy": strategy, "tag": "kindly-dns-query", "servers": dnsServers, "disableFallbackIfMatch": true}, "stats": map[string]any{}, "policy": map[string]any{"system": map[string]any{"statsInboundUplink": true, "statsInboundDownlink": true, "statsOutboundUplink": true, "statsOutboundDownlink": true}}}
	if awg != nil {
		root["tndtun_amnezia"] = awg
	}
	return root, nil
}
func ProfileName(p Profile) string {
	if p.Title != "" {
		return p.Title
	}
	if p.AmneziaName != "" {
		return p.AmneziaName
	}
	if p.Mode == "dns" {
		return p.DNS.Domain
	}
	return p.Server
}
func ResolverIP(s string) string {
	h, _, e := net.SplitHostPort(s)
	if e == nil {
		return h
	}
	return s
}
func Port(p string) int { n, _ := strconv.Atoi(p); return n }
func trimLines(s string) []string {
	r := []string{}
	for _, s := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == ',' || r == ';' }) {
		if s = strings.TrimSpace(s); s != "" {
			r = append(r, s)
		}
	}
	return r
}
