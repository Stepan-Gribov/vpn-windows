package libXray

import (
	"github.com/miekg/dns"
	"net/netip"
	"strings"
)

func desktopDNSAnswer(query, reply []byte) bool {
	var q, r dns.Msg
	if q.Unpack(query) != nil || r.Unpack(reply) != nil || !r.Response || q.Id != r.Id || len(q.Question) != 1 || len(r.Question) != 1 || q.Question[0] != r.Question[0] || r.Rcode != dns.RcodeSuccess {
		return false
	}
	name := strings.TrimSuffix(strings.ToLower(q.Question[0].Name), ".")
	local := name == "localhost" || strings.HasSuffix(name, ".localhost") || strings.HasSuffix(name, ".local") || strings.HasSuffix(name, ".lan") || strings.HasSuffix(name, ".home.arpa")
	if local {
		return true
	}
	for _, rr := range r.Answer {
		var ip netip.Addr
		switch a := rr.(type) {
		case *dns.A:
			ip, _ = netip.AddrFromSlice(a.A)
		case *dns.AAAA:
			ip, _ = netip.AddrFromSlice(a.AAAA)
		default:
			continue
		}
		ip = ip.Unmap()
		if !ip.IsValid() || ip.IsLoopback() || ip.IsUnspecified() {
			return false
		}
		if ip.Is4() && ip.As4()[0] == 0 {
			return false
		}
	}
	return true
}
