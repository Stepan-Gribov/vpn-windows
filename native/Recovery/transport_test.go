package transports

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KindlyVPN/foundation/transports/internal/dnsttclient"
	"github.com/miekg/dns"
	"github.com/xtaci/smux"
	"golang.org/x/net/proxy"
	"www.bamsoftware.com/git/dnstt.git/noise"
)

func echoListener(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return l
}

func roundTrip(t *testing.T, s session, count int) {
	t.Helper()
	c, err := s.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	payload := make([]byte, count)
	rand.Read(payload)
	done := make(chan error, 1)
	go func() { _, err := c.Write(payload); done <- err }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload changed")
	}
}

func TestHTTPSCarriesPayloadAndRejectsWrongServerKey(t *testing.T) {
	target := echoListener(t)
	private := make([]byte, 32)
	rand.Read(private)
	handler, err := RelayHandler(private, target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	cfg := HTTPSConfig{URL: server.URL, PublicKey: hex.EncodeToString(noise.PubkeyFromPrivkey(private))}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := dialHTTPS(ctx, cfg, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, 64*1024)
	s.Close()
	wrong := make([]byte, 32)
	rand.Read(wrong)
	cfg.PublicKey = hex.EncodeToString(wrong)
	if bad, err := dialHTTPS(ctx, cfg, server.Client()); err == nil {
		bad.Close()
		t.Fatal("wrong Noise key accepted")
	}
	if bad, err := openHTTPS(ctx, HTTPSConfig{URL: server.URL, PublicKey: hex.EncodeToString(noise.PubkeyFromPrivkey(private))}, nil); err == nil {
		bad.Close()
		t.Fatal("untrusted TLS certificate accepted")
	}
}

func TestSOCKSGateRejectsAnyOtherTarget(t *testing.T) {
	target := echoListener(t)
	gate, _ := net.Listen("tcp", "127.0.0.1:0")
	defer gate.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go serveSOCKSGate(ctx, gate, target.Addr().String())
	d, _ := proxy.SOCKS5("tcp", gate.Addr().String(), nil, proxy.Direct)
	c, err := d.Dial("tcp", target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	for _, addr := range []string{"127.0.0.1:1", "169.254.169.254:80", "example.com:443", "localhost:" + strconv.Itoa(target.Addr().(*net.TCPAddr).Port)} {
		if c, err := d.Dial("tcp", addr); err == nil {
			c.Close()
			t.Fatalf("unauthorized target accepted: %s", addr)
		}
	}
}

func TestSupervisorFallsBackAndCancelsActiveStreams(t *testing.T) {
	target := echoListener(t)
	key := make([]byte, 32)
	rand.Read(key)
	handler, _ := RelayHandler(key, target.Addr().String())
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	https := &HTTPSConfig{URL: server.URL, PublicKey: hex.EncodeToString(noise.PubkeyFromPrivkey(key))}
	reservation, _ := net.Listen("tcp", "127.0.0.1:0")
	address := reservation.Addr().String()
	reservation.Close()
	cfg := Config{Version: 1, Listen: address, Profiles: []Profile{{ID: "blocked", Type: "https", HTTPS: https}, {ID: "reachable", Type: "https", HTTPS: https}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan Status, 16)
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, cfg, func(s Status) { events <- s }, func(ctx context.Context, _ Config, p Profile) (session, error) {
			if p.ID == "blocked" {
				return nil, errors.New("simulated first-hop IP drop")
			}
			return dialHTTPS(ctx, *p.HTTPS, server.Client())
		})
	}()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	failed := false
	for {
		select {
		case event := <-events:
			if event.Profile == "blocked" && event.Stage == "failed" {
				failed = true
			}
			if event.Ready {
				if !failed || event.Profile != "reachable" {
					t.Fatal("wrong fallback order")
				}
				conn, err := net.DialTimeout("tcp", address, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				conn.Write([]byte("authenticated route"))
				got := make([]byte, 19)
				if _, err := io.ReadFull(conn, got); err != nil {
					t.Fatal(err)
				}
				if string(got) != "authenticated route" {
					t.Fatal("fallback payload changed")
				}
				cancel()
				select {
				case <-done:
					return
				case <-time.After(2 * time.Second):
					t.Fatal("active stream prevented cancellation")
				}
			}
		case err := <-done:
			t.Fatalf("supervisor exited early: %v", err)
		case <-timer.C:
			t.Fatal("supervisor did not select a reachable route")
		}
	}
}

func TestConfigRejectsUnsafeEndpointsAndUnknownFields(t *testing.T) {
	key := hex.EncodeToString(bytes.Repeat([]byte{1}, 32))
	for _, raw := range []string{
		`{"version":1,"listen":"0.0.0.0:9000","profiles":[{"id":"relay","type":"https","https":{"url":"https://edge.example/t","public_key":"` + key + `"}}]}`,
		`{"version":1,"profiles":[{"id":"relay","type":"https","https":{"url":"http://edge.example/t","public_key":"` + key + `"}}]}`,
		`{"version":1,"profiles":[{"id":"relay","type":"https","https":{"url":"https://user:secret@edge.example/t","public_key":"` + key + `"}}]}`,
		`{"version":1,"bootstrap_dns":["dns.example:53"],"profiles":[{"id":"relay","type":"https","https":{"url":"https://edge.example/t","public_key":"` + key + `"}}]}`,
		`{"version":1,"unknown_secret":"do-not-log","profiles":[]}`,
	} {
		if _, err := ParseConfig([]byte(raw)); err == nil {
			t.Fatal("unsafe configuration accepted")
		}
	}
	if _, err := RelayHandler(bytes.Repeat([]byte{1}, 32), "169.254.169.254:80"); err == nil {
		t.Fatal("non-loopback relay destination accepted")
	}
}

func TestReconnectAdvancesPastRouteWithFailedVPNProbe(t *testing.T) {
	key := hex.EncodeToString(bytes.Repeat([]byte{1}, 32))
	cfg := Config{Version: 1, StartAfter: "handshake-only", Profiles: []Profile{
		{ID: "handshake-only", Type: "https", HTTPS: &HTTPSConfig{URL: "https://edge.example/a", PublicKey: key}},
		{ID: "next-route", Type: "https", HTTPS: &HTTPSConfig{URL: "https://edge.example/b", PublicKey: key}},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var attempted string
	_ = run(ctx, cfg, nil, func(_ context.Context, _ Config, p Profile) (session, error) {
		attempted = p.ID
		cancel()
		return nil, context.Canceled
	})
	if attempted != "next-route" {
		t.Fatalf("repeated a route whose VPN probe failed: %s", attempted)
	}
}

func TestStreamOpenCancelsBlockedCarrier(t *testing.T) {
	for _, transport := range []string{"dnstt", "https"} {
		t.Run(transport, func(t *testing.T) {
			client, peer := net.Pipe()
			defer peer.Close() // The peer never reads the stream-opening frame.
			mux, err := smux.Client(client, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer mux.Close()
			var s session = &httpsSession{Session: mux, close: func() { mux.Close() }}
			if transport == "dnstt" {
				s = dnsSession{&dnsttclient.Session{Session: mux}}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				stream, err := s.Open(ctx)
				if stream != nil {
					stream.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("stream open did not report its deadline: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("stream open ignored its context")
			}
			select {
			case <-s.Done():
			case <-time.After(time.Second):
				t.Fatal("failed carrier did not release the supervisor")
			}
		})
	}
}

func TestScopedIPv6ResolverSurvivesValidationAndSelection(t *testing.T) {
	resolver := "[fe80::1%wlan0]:53"
	cfg := Config{Version: 1, BootstrapDNS: []string{resolver}, Profiles: []Profile{{
		ID: "dns", Type: "dnstt", DNS: &DNSConfig{Domain: "t.example.test",
			PublicKey: hex.EncodeToString(bytes.Repeat([]byte{1}, 32))},
	}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	selected := ResolverCandidates(cfg.BootstrapDNS, []string{"192.0.2.53:53"})
	if len(selected) != 2 || selected[0] != resolver {
		t.Fatalf("lost the network resolver scope: %v", selected)
	}
	address, err := net.ResolveUDPAddr("udp", selected[0])
	if err != nil || address.Zone != "wlan0" {
		t.Fatalf("lost the interface zone: %v %v", address, err)
	}
}

// Uses the unmodified official server through a recursive forwarding fixture.
// This verifies protocol interoperability, cache-busting queries, resolver
// fallback, end-to-end authentication, payload integrity and shutdown.
func TestDNSTTThroughRecursiveResolver(t *testing.T) {
	if testing.Short() {
		t.Skip("builds official dnstt server")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "dnstt-server")
	build := exec.Command("go", "build", "-o", binary, "./dnstt-server")
	build.Dir = "third_party/dnstt" // retain the upstream release's dependency versions
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("server build: %v %s", err, out)
	}
	key := make([]byte, 32)
	rand.Read(key)
	keyPath := filepath.Join(dir, "server.key")
	os.WriteFile(keyPath, []byte(hex.EncodeToString(key)), 0600)
	target := echoListener(t)
	reservation, _ := net.ListenPacket("udp", "127.0.0.1:0")
	authoritative := reservation.LocalAddr().String()
	reservation.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	server := exec.CommandContext(ctx, binary, "-udp", authoritative, "-privkey-file", keyPath, "t.example.test", target.Addr().String())
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); server.Wait() }()
	resolver, _ := net.ListenPacket("udp", "127.0.0.1:0")
	var replies atomic.Int32
	forwarder := &dns.Server{PacketConn: resolver, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		a, _, err := (&dns.Client{Timeout: 2 * time.Second}).ExchangeContext(ctx, q, authoritative)
		if err == nil {
			replies.Add(1)
			w.WriteMsg(a)
		}
	})}
	go forwarder.ActivateAndServe()
	defer forwarder.Shutdown()
	silent, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer silent.Close()
	p := Profile{ID: "dns", Type: "dnstt", DNS: &DNSConfig{Domain: "t.example.test", PublicKey: hex.EncodeToString(noise.PubkeyFromPrivkey(key)), Resolvers: []string{silent.LocalAddr().String(), resolver.LocalAddr().String()}}}
	s, err := connect(ctx, Config{}, p)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, 8*1024)
	if replies.Load() < 2 {
		t.Fatal("did not receive recursive responses")
	}
	s.Close()
	select {
	case <-s.Done():
	case <-time.After(time.Second):
		t.Fatal("DNS session did not stop")
	}
	bad := make([]byte, 32)
	rand.Read(bad)
	p.DNS.PublicKey = hex.EncodeToString(bad)
	p.DNS.Resolvers = []string{resolver.LocalAddr().String()}
	if badSession, err := connect(ctx, Config{}, p); err == nil {
		badSession.Close()
		t.Fatal("wrong DNS key accepted")
	}
}
