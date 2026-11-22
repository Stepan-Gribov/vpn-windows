package libXray

// User-VPN direct DNS is separate from the panel bootstrap. This loopback-only
// bridge binds each upstream socket to the latest physical interface; Xray uses
// tcp+local:// so DNS never recursively re-enters its own tunnel dispatcher.
import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"sync"
	"time"
)

type physicalDNSBridge struct {
	listener  net.Listener
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	name      string
	resolvers []string
	clients   map[net.Conn]bool
	slots     chan struct{}
	wg        sync.WaitGroup
}

var physicalDNSState struct {
	sync.Mutex
	bridge *physicalDNSBridge
}

func KindlyPhysicalDNSStart(name, rawResolvers string) int32 {
	var resolvers []string
	if json.Unmarshal([]byte(rawResolvers), &resolvers) != nil {
		return 0
	}
	if _, err := panelControl(name); err != nil {
		return 0
	}
	physicalDNSState.Lock()
	defer physicalDNSState.Unlock()
	if b := physicalDNSState.bridge; b != nil {
		b.mu.Lock()
		b.name = name
		b.resolvers = append([]string(nil), resolvers...)
		b.mu.Unlock()
		return int32(b.listener.Addr().(*net.TCPAddr).Port)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &physicalDNSBridge{listener: listener, ctx: ctx, cancel: cancel, name: name, resolvers: resolvers, clients: make(map[net.Conn]bool), slots: make(chan struct{}, 16)}
	physicalDNSState.bridge = b
	b.wg.Add(1)
	go b.accept()
	return int32(listener.Addr().(*net.TCPAddr).Port)
}
func KindlyPhysicalDNSStop() {
	physicalDNSState.Lock()
	defer physicalDNSState.Unlock()
	b := physicalDNSState.bridge
	if b == nil {
		return
	}
	physicalDNSState.bridge = nil
	b.cancel()
	b.listener.Close()
	b.mu.Lock()
	for c := range b.clients {
		c.Close()
	}
	b.mu.Unlock()
	b.wg.Wait()
}
func (b *physicalDNSBridge) accept() {
	defer b.wg.Done()
	for {
		c, err := b.listener.Accept()
		if err != nil {
			return
		}
		// Apply backpressure to accept instead of resetting the next DNS client.
		// The worker bound stays fixed; queued callers can use the TCP backlog.
		select {
		case b.slots <- struct{}{}:
		case <-b.ctx.Done():
			c.Close()
			return
		}
		b.mu.Lock()
		if b.ctx.Err() != nil {
			b.mu.Unlock()
			c.Close()
			<-b.slots
			return
		}
		b.clients[c] = true
		b.mu.Unlock()
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			defer func() { c.Close(); b.mu.Lock(); delete(b.clients, c); b.mu.Unlock(); <-b.slots }()
			b.serve(c)
		}()
	}
}
func (b *physicalDNSBridge) serve(c net.Conn) {
	for {
		c.SetDeadline(time.Now().Add(12 * time.Second))
		var length [2]byte
		if _, err := io.ReadFull(c, length[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(length[:]))
		if n < 12 || n > 4096 {
			return
		}
		query := make([]byte, n)
		if _, err := io.ReadFull(c, query); err != nil {
			return
		}
		b.mu.Lock()
		name, resolvers := b.name, append([]string(nil), b.resolvers...)
		b.mu.Unlock()
		reply := physicalDNSQuery(b.ctx, name, resolvers, query)
		if len(reply) == 0 { // SERVFAIL, preserving the query's ID and question.
			reply = append([]byte(nil), query...)
			reply[2] = (reply[2] & 1) | 0x80
			reply[3] = (reply[3] & 0x10) | 0x82
			clear(reply[6:12])
		}
		binary.BigEndian.PutUint16(length[:], uint16(len(reply)))
		if _, err := c.Write(append(length[:], reply...)); err != nil {
			return
		}
	}
}
func physicalDNSQuery(ctx context.Context, name string, resolvers []string, query []byte) []byte {
	control, err := panelControl(name)
	if err != nil {
		return nil
	}
	for _, server := range resolvers {
		host, _, err := net.SplitHostPort(server)
		if err != nil || net.ParseIP(host) == nil {
			continue
		}
		request, cancel := context.WithTimeout(ctx, 3*time.Second)
		dialer := net.Dialer{Control: control, Timeout: 2 * time.Second}
		conn, err := dialer.DialContext(request, "udp", server)
		if err != nil {
			cancel()
			continue
		}
		stop := context.AfterFunc(request, func() { conn.Close() })
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, err = conn.Write(query)
		reply := make([]byte, 65535)
		n := 0
		if err == nil {
			n, err = conn.Read(reply)
		}
		stop()
		conn.Close()
		cancel()
		if err == nil && n >= 12 && reply[0] == query[0] && reply[1] == query[1] && reply[2]&0x80 != 0 && reply[3]&15 == 0 {
			return reply[:n]
		}
		if ctx.Err() != nil {
			return nil
		}
	}
	return nil
}
