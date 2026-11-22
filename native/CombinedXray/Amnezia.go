package libXray

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	awgdevice "github.com/amnezia-vpn/amneziawg-go/v3/device"
	awgtun "github.com/amnezia-vpn/amneziawg-go/v3/tun"
	wgtun "golang.zx2c4.com/wireguard/tun"
	"kindlyvpn/native/internal/amnezianetstack"
)

const amneziaSOCKSAddress = "127.0.0.1:9004"

type amneziaConfig struct {
	Addresses []string `json:"addresses"`
	DNS       []string `json:"dns"`
	MTU       int      `json:"mtu"`
	UAPI      string   `json:"uapi"`
}

// Reuse the current netstack already linked by Xray. AWG uses the same packet
// device contract, with a separately named event type. No OS TUN is created.
type amneziaTUN struct {
	wgtun.Device
	events chan awgtun.Event
}

func (t *amneziaTUN) Events() <-chan awgtun.Event { return t.events }
func adaptAmneziaTUN(t wgtun.Device) *amneziaTUN {
	a := &amneziaTUN{Device: t, events: make(chan awgtun.Event, 10)}
	go func() {
		defer close(a.events)
		for event := range t.Events() {
			a.events <- awgtun.Event(event)
		}
	}()
	return a
}

func amneziaFromFile(path string) (*amneziaConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root struct {
		Config *amneziaConfig `json:"tndtun_amnezia"`
	}
	if err = json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	if root.Config != nil {
		err = root.Config.validate()
	}
	return root.Config, err
}
func (c amneziaConfig) validate() error {
	if len(c.Addresses) == 0 || len(c.Addresses) > 8 || len(c.DNS) > 8 || c.MTU < 576 || c.MTU > 1500 || len(c.UAPI) > 65536 {
		return errors.New("invalid Amnezia interface settings")
	}
	for _, value := range append(append([]string{}, c.Addresses...), c.DNS...) {
		if _, err := netip.ParseAddr(value); err != nil {
			return errors.New("invalid Amnezia IP address")
		}
	}
	// Only client connection fields, never filesystem paths or executable hooks.
	allowed := map[string]bool{}
	for _, name := range strings.Fields("private_key public_key preshared_key replace_peers endpoint persistent_keepalive_interval replace_allowed_ips allowed_ip jc jmin jmax s1 s2 s3 s4 h1 h2 h3 h4 i1 i2 i3 i4 i5 header_protection_key content_padding_addition rekey_after_time rekey_timeout reject_after_time keepalive_timeout max_handshake_attempts random_trailers disable_cookies") {
		allowed[name] = true
	}
	for _, line := range strings.Split(c.UAPI, "\n") {
		if line == "" {
			continue
		}
		name, _, ok := strings.Cut(line, "=")
		if !ok || !allowed[name] {
			return errors.New("unsupported Amnezia configuration field")
		}
	}
	return nil
}

type amneziaProxy struct {
	device      *awgdevice.Device
	network     *netstack.Net
	listener    net.Listener
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.Mutex
	sockets     map[io.Closer]struct{}
	workers     sync.WaitGroup
	closeOnce   sync.Once
	bindRefresh chan struct{}
}

func newAmneziaProxy(c amneziaConfig, listen string) (*amneziaProxy, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	addresses := make([]netip.Addr, 0, len(c.Addresses))
	dns := make([]netip.Addr, 0, len(c.DNS))
	for _, value := range c.Addresses {
		addresses = append(addresses, netip.MustParseAddr(value))
	}
	for _, value := range c.DNS {
		dns = append(dns, netip.MustParseAddr(value))
	}
	tun, network, err := netstack.CreateNetTUN(addresses, dns, c.MTU)
	if err != nil {
		return nil, err
	}
	if err := network.SetTCPBuffers(512); err != nil {
		tun.Close()
		return nil, err
	}
	logger := awgdevice.NewLogger(awgdevice.LogLevelSilent, "Amnezia: ")
	device := awgdevice.NewDevice(adaptAmneziaTUN(tun), newDesktopAwareBind(), logger)
	// Configure before creating peers, as required by upstream mobilequirks.go.
	device.DisableSomeRoamingForBrokenMobileSemantics()
	if err = device.IpcSet(c.UAPI); err != nil {
		device.Close()
		return nil, errors.New("invalid Amnezia protocol parameters")
	}
	if err = device.Up(); err != nil {
		device.Close()
		return nil, fmt.Errorf("start Amnezia: %w", err)
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		device.Close()
		return nil, fmt.Errorf("start Amnezia proxy: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &amneziaProxy{device: device, network: network, listener: listener, ctx: ctx, cancel: cancel, sockets: map[io.Closer]struct{}{}, bindRefresh: make(chan struct{}, 1)}
	p.workers.Add(2)
	go p.serve()
	go p.refreshBindings()
	return p, nil
}

// Refresh only the encrypted UDP sockets after a physical path change/wake.
// One lifetime worker coalesces events and stops with this proxy. Neither the
// device, the router nor any application TCP sessions are reconstructed.
func (p *amneziaProxy) networkChanged() bool {
	if p.ctx.Err() != nil {
		return false
	}
	select {
	case p.bindRefresh <- struct{}{}:
	default:
	}
	return true
}
func (p *amneziaProxy) refreshBindings() {
	defer p.workers.Done()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-p.bindRefresh:
		}
		for attempt := 0; attempt < 10; attempt++ {
			if p.ctx.Err() != nil {
				return
			}
			if err := p.device.BindUpdate(); err == nil {
				p.device.SendKeepalivesToPeersWithCurrentKeypair()
				break
			}
			timer := time.NewTimer(500 * time.Millisecond)
			select {
			case <-p.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}
}

func (p *amneziaProxy) track(c io.Closer) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ctx.Err() != nil {
		c.Close()
		return false
	}
	p.sockets[c] = struct{}{}
	return true
}
func (p *amneziaProxy) untrack(c io.Closer) {
	c.Close()
	p.mu.Lock()
	delete(p.sockets, c)
	p.mu.Unlock()
}
func (p *amneziaProxy) Close() {
	p.closeOnce.Do(func() {
		p.cancel()
		p.listener.Close()
		p.mu.Lock()
		for socket := range p.sockets {
			socket.Close()
		}
		p.mu.Unlock()
		p.device.Close()
		p.workers.Wait()
	})
}
func (p *amneziaProxy) serve() {
	defer p.workers.Done()
	slots := make(chan struct{}, 256)
	for {
		local, err := p.listener.Accept()
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			local.Close()
			continue
		}
		if !p.track(local) {
			<-slots
			return
		}
		p.workers.Add(1)
		go func() { defer p.workers.Done(); defer func() { <-slots }(); defer p.untrack(local); p.handle(local) }()
	}
}
func readAmneziaAddress(reader io.Reader, kind byte) (string, error) {
	var host string
	switch kind {
	case 1, 4:
		size := 4
		if kind == 4 {
			size = 16
		}
		value := make([]byte, size)
		if _, err := io.ReadFull(reader, value); err != nil {
			return "", err
		}
		host = net.IP(value).String()
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(reader, size[:]); err != nil {
			return "", err
		}
		if size[0] == 0 {
			return "", errors.New("empty SOCKS address")
		}
		value := make([]byte, int(size[0]))
		if _, err := io.ReadFull(reader, value); err != nil {
			return "", err
		}
		host = string(value)
	default:
		return "", errors.New("invalid SOCKS address")
	}
	var port [2]byte
	if _, err := io.ReadFull(reader, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(port[:]))), nil
}
func amneziaAddressBytes(address *net.UDPAddr) []byte {
	result := []byte{1}
	ip := address.IP.To4()
	if ip == nil {
		result[0] = 4
		ip = address.IP.To16()
	}
	result = append(result, ip...)
	return binary.BigEndian.AppendUint16(result, uint16(address.Port))
}
func (p *amneziaProxy) handle(local net.Conn) {
	local.SetDeadline(time.Now().Add(15 * time.Second))
	var greeting [2]byte
	if _, err := io.ReadFull(local, greeting[:]); err != nil || greeting[0] != 5 || greeting[1] == 0 {
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(local, methods); err != nil {
		return
	}
	if !bytes.Contains(methods, []byte{0}) {
		local.Write([]byte{5, 255})
		return
	}
	if _, err := local.Write([]byte{5, 0}); err != nil {
		return
	}
	var request [4]byte
	if _, err := io.ReadFull(local, request[:]); err != nil || request[0] != 5 || request[2] != 0 {
		return
	}
	target, err := readAmneziaAddress(local, request[3])
	if err != nil {
		return
	}
	switch request[1] {
	case 1:
		ctx, cancel := context.WithTimeout(p.ctx, 15*time.Second)
		remote, err := p.network.DialContext(ctx, "tcp", target)
		cancel()
		if err != nil {
			local.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		if !p.track(remote) {
			return
		}
		defer p.untrack(remote)
		if _, err = local.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}
		local.SetDeadline(time.Time{})
		done := make(chan struct{})
		go func() { amneziaCopyHalfClosed(remote, local); close(done) }()
		amneziaCopyHalfClosed(local, remote)
		<-done
	case 3:
		p.associateUDP(local)
	default:
		local.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
	}
}

// A UDP association lives exactly as long as its TCP control connection.
// Each destination retains one UDP socket, so replies preserve source addresses
// and QUIC/DNS work without a TCP fallback. Both flow count and idle life are bounded.
func (p *amneziaProxy) associateUDP(control net.Conn) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return
	}
	if !p.track(udp) {
		return
	}
	defer p.untrack(udp)
	reply := append([]byte{5, 0, 0}, amneziaAddressBytes(udp.LocalAddr().(*net.UDPAddr))...)
	if _, err = control.Write(reply); err != nil {
		return
	}
	control.SetDeadline(time.Time{})
	ctx, cancel := context.WithCancel(p.ctx)
	defer cancel()
	var workers sync.WaitGroup
	go func() { io.Copy(io.Discard, control); cancel(); udp.Close() }()
	type flow struct {
		conn   net.Conn
		header []byte
	}
	flows := map[string]*flow{}
	var mu sync.Mutex
	defer func() {
		cancel()
		udp.Close()
		control.Close()
		mu.Lock()
		for _, f := range flows {
			f.conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	}()
	buffer := make([]byte, 65535)
	var client *net.UDPAddr
	for {
		n, source, err := udp.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		if client == nil {
			client = source
		} else if client.String() != source.String() {
			continue
		}
		if n < 4 || buffer[0] != 0 || buffer[1] != 0 || buffer[2] != 0 {
			continue
		}
		reader := bytes.NewReader(buffer[4:n])
		target, err := readAmneziaAddress(reader, buffer[3])
		if err != nil {
			continue
		}
		headerSize := n - reader.Len()
		payload := buffer[headerSize:n]
		mu.Lock()
		f := flows[target]
		mu.Unlock()
		if f == nil {
			mu.Lock()
			full := len(flows) >= 64
			mu.Unlock()
			if full {
				continue
			}
			dialCtx, stop := context.WithTimeout(ctx, 10*time.Second)
			remote, err := p.network.DialContext(dialCtx, "udp", target)
			stop()
			if err != nil {
				continue
			}
			if !p.track(remote) {
				return
			}
			f = &flow{conn: remote, header: append([]byte(nil), buffer[:headerSize]...)}
			mu.Lock()
			flows[target] = f
			mu.Unlock()
			workers.Add(1)
			go func(target string, f *flow, client *net.UDPAddr) {
				defer workers.Done()
				defer p.untrack(f.conn)
				defer func() {
					mu.Lock()
					if flows[target] == f {
						delete(flows, target)
					}
					mu.Unlock()
				}()
				packet := make([]byte, 65535)
				for {
					f.conn.SetReadDeadline(time.Now().Add(120 * time.Second))
					n, err := f.conn.Read(packet)
					if err != nil {
						return
					}
					response := append(append([]byte(nil), f.header...), packet[:n]...)
					if _, writeErr := udp.WriteToUDP(response, client); writeErr != nil {
						return
					}
				}
			}(target, f, client)
		}
		f.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err = f.conn.Write(payload); err != nil {
			f.conn.Close()
		}
	}
}

// A TCP FIN ends one direction, not the response in the opposite direction.
// Both native TCP and the encrypted netstack connection support CloseWrite.
func amneziaCopyHalfClosed(destination, source net.Conn) {
	_, err := io.Copy(destination, source)
	if err == nil {
		if half, ok := destination.(interface{ CloseWrite() error }); ok {
			if half.CloseWrite() == nil {
				return
			}
		}
	}
	// An actual copy error must also unblock the other relay goroutine.
	destination.Close()
	source.Close()
}
