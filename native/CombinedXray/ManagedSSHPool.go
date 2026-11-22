package libXray

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/KindlyVPN/foundation/transports"
	"golang.org/x/crypto/ssh"
)

type managedSSHTarget struct{}

type managedSSHSession struct {
	client *ssh.Client
	done   chan struct{}
}

func (s *managedSSHSession) Done() <-chan struct{} { return s.done }
func (s *managedSSHSession) Close() error          { return s.client.Close() }
func (s *managedSSHSession) Open(ctx context.Context) (io.ReadWriteCloser, error) {
	target, ok := ctx.Value(managedSSHTarget{}).(string)
	if !ok {
		return nil, errors.New("SSH destination missing")
	}
	return s.client.DialContext(ctx, "tcp", target)
}

// Each SSH client uses a separate DNSTT stream. A single shared SSH client would
// put all application connections back onto one DNS lane despite the DNS pool.
func openManagedSSHSession(ctx context.Context, conn net.Conn, carrier transports.PoolSession, config *ssh.ClientConfig) (*managedSSHSession, error) {
	stop := context.AfterFunc(ctx, func() { conn.Close(); carrier.Close() })
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	sshConn, channels, requests, err := ssh.NewClientConn(conn, "dns-tunnel", config)
	if err != nil {
		stop()
		conn.Close()
		carrier.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	s := &managedSSHSession{client: ssh.NewClient(sshConn, channels, requests), done: make(chan struct{})}
	go func() { s.client.Wait(); stop(); conn.Close(); carrier.Close(); close(s.done) }()
	return s, nil
}
