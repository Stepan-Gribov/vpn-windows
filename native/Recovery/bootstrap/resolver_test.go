package bootstrap

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestSilentUDPResolverFallsBackOnResponse(t *testing.T) {
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	working, _ := net.ListenPacket("udp", "127.0.0.1:0")
	server := &dns.Server{PacketConn: working, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		a := new(dns.Msg).SetReply(q)
		if q.Question[0].Qtype == dns.TypeA {
			a.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.42")}}
		}
		w.WriteMsg(a)
	})}
	go server.ActivateAndServe()
	defer server.Shutdown()
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	values, err := Resolver([]string{silent.LocalAddr().String(), working.LocalAddr().String()}).LookupIP(ctx, "ip4", "fresh.example.test")
	if err != nil || len(values) != 1 || !values[0].Equal(net.ParseIP("192.0.2.42")) {
		t.Fatalf("response fallback: %v %v", values, err)
	}
}

func TestResolverCancellationDoesNotWaitForFallbacks(t *testing.T) {
	silent, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer silent.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := Resolver([]string{silent.LocalAddr().String()}).LookupIP(ctx, "ip4", "cancel.example.test")
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled lookup succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("lookup ignored cancellation")
	}
}

func TestNoConfigurationPreservesSystemResolver(t *testing.T) {
	if Resolver(nil) != nil {
		t.Fatal("system DNS overridden")
	}
}
