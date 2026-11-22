package libXray

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func panelControl(name string) (func(string, string, syscall.RawConn) error, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil || strings.HasPrefix(name, "utun") || name == "lo0" || iface.Index == 0 {
		return nil, errors.New("no physical interface")
	}
	return func(network, address string, raw syscall.RawConn) error {
		var failure error
		err := raw.Control(func(fd uintptr) {
			host, _, _ := net.SplitHostPort(address)
			if strings.HasSuffix(network, "6") || net.ParseIP(host) != nil && net.ParseIP(host).To4() == nil {
				failure = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, iface.Index)
			} else {
				failure = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, iface.Index)
			}
		})
		if err != nil {
			return err
		}
		return failure
	}, nil
}
func panelPhysicalHTTP(name string, servers []string, timeout time.Duration) (*http.Client, error) {
	control, err := panelControl(name)
	if err != nil {
		return nil, err
	}
	physical := &net.Dialer{Timeout: 8 * time.Second, Control: control}
	// Never resolve the API/DoH host using a running VPN's injected DNS.
	physical.Resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		for _, server := range servers {
			host, _, err := net.SplitHostPort(server)
			if err != nil || net.ParseIP(host) == nil {
				continue
			}
			if conn, err := physical.DialContext(ctx, network, server); err == nil {
				return conn, nil
			}
		}
		return nil, errors.New("physical DNS unavailable")
	}}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 8 * time.Second,
		MaxResponseHeaderBytes: 32768, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			// Public DoH addresses, with the original HTTPS hostname still used for TLS.
			switch host {
			case "dns.google":
				address = net.JoinHostPort("8.8.8.8", port)
			case "cloudflare-dns.com":
				address = net.JoinHostPort("1.1.1.1", port)
			}
			return physical.DialContext(ctx, network, address)
		}}
	return panelClient(transport, timeout), nil
}

func panelDNSWire(ctx context.Context, name, resolver string) (net.PacketConn, net.Addr, error) {
	if strings.HasPrefix(resolver, "https://") {
		u, err := url.Parse(resolver)
		if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/dns-query" ||
			(u.Hostname() != "dns.google" && u.Hostname() != "cloudflare-dns.com") {
			return nil, nil, errors.New("unsupported DoH resolver")
		}
		client, err := panelPhysicalHTTP(name, nil, 8*time.Second)
		if err != nil {
			return nil, nil, err
		}
		child, cancel := context.WithCancel(ctx)
		wire := &panelDoH{ctx: child, cancel: cancel, client: client, url: resolver, replies: make(chan []byte, 32), slots: make(chan struct{}, 16)}
		return wire, &net.UDPAddr{IP: net.IPv4(0, 0, 0, 1), Port: 53}, nil
	}
	remote, err := net.ResolveUDPAddr("udp", resolver)
	if err != nil {
		return nil, nil, err
	}
	if host, _, err := net.SplitHostPort(resolver); err != nil || net.ParseIP(host) == nil {
		return nil, nil, errors.New("literal DNS IP required")
	}
	control, err := panelControl(name)
	if err != nil {
		return nil, nil, err
	}
	family := "udp4"
	if remote.IP.To4() == nil {
		family = "udp6"
	}
	config := net.ListenConfig{Control: control}
	wire, err := config.ListenPacket(ctx, family, ":0")
	return wire, remote, err
}

type panelDoH struct {
	ctx     context.Context
	cancel  context.CancelFunc
	client  *http.Client
	url     string
	replies chan []byte
	slots   chan struct{}
	workers sync.WaitGroup
	once    sync.Once
	mu      sync.Mutex
	closed  bool
}

func (c *panelDoH) ReadFrom(buffer []byte) (int, net.Addr, error) {
	select {
	case <-c.ctx.Done():
		return 0, nil, net.ErrClosed
	case data := <-c.replies:
		return copy(buffer, data), &net.UDPAddr{IP: net.IPv4(0, 0, 0, 1), Port: 53}, nil
	}
}
func (c *panelDoH) WriteTo(data []byte, _ net.Addr) (int, error) {
	select {
	case <-c.ctx.Done():
		return 0, net.ErrClosed
	case c.slots <- struct{}{}:
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		<-c.slots
		return 0, net.ErrClosed
	}
	c.workers.Add(1)
	c.mu.Unlock()
	packet := append([]byte(nil), data...)
	go func() {
		defer c.workers.Done()
		defer func() { <-c.slots }()
		ctx, stop := context.WithTimeout(c.ctx, 8*time.Second)
		defer stop()
		request, err := http.NewRequestWithContext(ctx, "POST", c.url, strings.NewReader(string(packet)))
		if err != nil {
			return
		}
		request.Header.Set("Content-Type", "application/dns-message")
		request.Header.Set("Accept", "application/dns-message")
		response, err := c.client.Do(request)
		if err != nil {
			return
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			return
		}
		reply, err := io.ReadAll(io.LimitReader(response.Body, 65536))
		if err != nil || len(reply) > 65535 {
			return
		}
		select {
		case c.replies <- reply:
		case <-ctx.Done():
		}
	}()
	return len(data), nil
}
func (c *panelDoH) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		c.cancel()
		c.client.CloseIdleConnections()
		c.workers.Wait()
	})
	return nil
}
func (c *panelDoH) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *panelDoH) SetDeadline(time.Time) error      { return nil }
func (c *panelDoH) SetReadDeadline(time.Time) error  { return nil }
func (c *panelDoH) SetWriteDeadline(time.Time) error { return nil }
