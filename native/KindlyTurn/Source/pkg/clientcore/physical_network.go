package clientcore

import (
	"context"
	"net"
	"sync"
	"syscall"
	"time"
)

var physicalNetwork struct {
	sync.RWMutex
	control func(string, string, syscall.RawConn) error
}

// SetPhysicalSocketControl is scoped to the Windows-owned engine copy. Nil retains original behavior.
func SetPhysicalSocketControl(c func(string, string, syscall.RawConn) error) {
	physicalNetwork.Lock()
	physicalNetwork.control = c
	physicalNetwork.Unlock()
}
func socketControl() func(string, string, syscall.RawConn) error {
	physicalNetwork.RLock()
	defer physicalNetwork.RUnlock()
	return physicalNetwork.control
}
func physicalDialer() net.Dialer {
	return net.Dialer{Timeout: 20 * time.Second, KeepAlive: 30 * time.Second, Control: socketControl()}
}
func physicalUDP(network string, l, r *net.UDPAddr) (*net.UDPConn, error) {
	d := physicalDialer()
	if l != nil {
		d.LocalAddr = l
	}
	c, e := d.Dial(network, r.String())
	if e != nil {
		return nil, e
	}
	return c.(*net.UDPConn), nil
}
func physicalListenUDP(network string, l *net.UDPAddr) (*net.UDPConn, error) {
	address := ":0"
	if l != nil {
		address = l.String()
	}
	lc := net.ListenConfig{Control: socketControl()}
	c, e := lc.ListenPacket(context.Background(), network, address)
	if e != nil {
		return nil, e
	}
	return c.(*net.UDPConn), nil
}
func physicalDialTCP(network string, l, r *net.TCPAddr) (*net.TCPConn, error) {
	d := physicalDialer()
	if l != nil {
		d.LocalAddr = l
	}
	c, e := d.Dial(network, r.String())
	if e != nil {
		return nil, e
	}
	return c.(*net.TCPConn), nil
}
