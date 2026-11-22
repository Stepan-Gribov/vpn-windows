package libXray

import (
	"context"
	"errors"
	"net"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsDNSWireNeverResolvesInvalidUpstream(t *testing.T) {
	previous := net.DefaultResolver
	defer func() { net.DefaultResolver = previous }()
	lookups := 0
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		lookups++
		return nil, errors.New("unexpected system DNS lookup")
	}}
	_, _, err := panelDNSWire(context.Background(), "", "untrusted.tndtun.invalid:53")
	if err == nil || err.Error() != "literal DNS IP required" || lookups != 0 {
		t.Fatalf("invalid DNS upstream caused a lookup: %v, lookups=%d", err, lookups)
	}
}

func TestWindowsPhysicalControlRejectsUnsafeInterfaces(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"", "TnDtun-does-not-exist", "no-such-tndtun-interface"}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			names = append(names, iface.Name)
		}
	}
	for _, name := range names {
		if _, err := panelControl(name); err == nil {
			t.Fatalf("unsafe interface accepted: %q", name)
		}
	}
}

// Check the real Windows socket option, including its unusual IPv4 byte order.
// No packet is sent and no adapter, address, route or DNS setting is changed.
func TestWindowsInterfaceBindingSocketOptions(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		control, err := panelControl(iface.Name)
		if err != nil {
			continue
		}
		for _, family := range []string{"udp4", "udp6"} {
			t.Run(iface.Name+"/"+family, func(t *testing.T) {
				lc := net.ListenConfig{Control: control}
				conn, err := lc.ListenPacket(context.Background(), family, ":0")
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				raw, err := conn.(*net.UDPConn).SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				var value int
				var failure error
				err = raw.Control(func(fd uintptr) {
					level, option := windows.IPPROTO_IP, ipUnicastIF
					if family == "udp6" {
						level, option = windows.IPPROTO_IPV6, ipv6UnicastIF
					}
					value, failure = windows.GetsockoptInt(windows.Handle(fd), level, option)
				})
				if err != nil || failure != nil {
					t.Fatalf("socket option: %v %v", err, failure)
				}
				// Windows accepts IP_UNICAST_IF in network byte order but returns
				// the interface index in host byte order (unlike a raw roundtrip).
				if value != iface.Index {
					t.Fatalf("bound to interface %d, want %d", value, iface.Index)
				}
			})
		}
		return
	}
	t.Fatal("no usable interface available for socket-binding validation")
}
