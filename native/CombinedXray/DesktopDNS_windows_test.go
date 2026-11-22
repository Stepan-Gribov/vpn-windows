package libXray

import (
	"github.com/miekg/dns"
	"testing"
)

func TestWindowsPhysicalDNSRejectsPoisonAndMismatchedReply(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("public.example.", dns.TypeA)
	query, _ := q.Pack()
	for _, ip := range []string{"127.0.0.1", "0.0.0.0", "0.12.1.1", "203.0.113.1"} {
		r := new(dns.Msg)
		r.SetReply(q)
		a, _ := dns.NewRR("public.example. 60 IN A " + ip)
		r.Answer = []dns.RR{a}
		raw, _ := r.Pack()
		if desktopDNSAnswer(query, raw) != (ip == "203.0.113.1") {
			t.Fatal("DNS answer validation:", ip)
		}
		r.Id++
		raw, _ = r.Pack()
		if desktopDNSAnswer(query, raw) {
			t.Fatal("accepted different transaction ID")
		}
	}
	q.SetQuestion("printer.local.", dns.TypeA)
	query, _ = q.Pack()
	r := new(dns.Msg)
	r.SetReply(q)
	a, _ := dns.NewRR("printer.local. 60 IN A 192.168.1.10")
	r.Answer = []dns.RR{a}
	raw, _ := r.Pack()
	if !desktopDNSAnswer(query, raw) {
		t.Fatal("local network answer rejected")
	}
}
