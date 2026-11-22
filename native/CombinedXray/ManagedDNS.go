package libXray

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/KindlyVPN/foundation/transports"
	"golang.org/x/crypto/ssh"
)

type managedDNSConfig struct {
	BuiltIn           bool     `json:"built_in"`
	PhysicalInterface string   `json:"physical_interface"`
	Resolvers         []string `json:"resolvers"`
	SessionCount      int      `json:"session_count"`
	Domain            string   `json:"domain"`
	Resolver          string   `json:"resolver"`
	PublicKey         string   `json:"public_key"`
	TunnelType        string   `json:"tunnel_type"`
	Username          string   `json:"ssh_username"`
	Password          string   `json:"ssh_password"`
	PrivateKey        string   `json:"ssh_private_key"`
	HostKey           string   `json:"ssh_host_key"`
}

func (c managedDNSConfig) sessions() int {
	if c.SessionCount == 0 {
		return 4
	}
	return c.SessionCount
}

func (c managedDNSConfig) carrier() (transports.Config, error) {
	if c.sessions() != 1 && c.sessions() != 2 && c.sessions() != 4 && c.sessions() != 8 {
		return transports.Config{}, errors.New("unsupported DNS session count")
	}
	port := "9002"
	if c.TunnelType == "ssh" {
		port = "9003"
	} else if c.TunnelType != "socks5" {
		return transports.Config{}, errors.New("unsupported DNS tunnel type")
	}
	cfg := transports.Config{Version: 1, Listen: "127.0.0.1:" + port, Profiles: []transports.Profile{{ID: "managed_dns", Type: "dnstt", DNS: &transports.DNSConfig{Domain: c.Domain, PublicKey: c.PublicKey, Resolvers: []string{c.Resolver}, SessionCount: c.sessions(), MaxQPS: 800}}}}
	return cfg, cfg.Validate()
}

func (c managedDNSConfig) sshConfig() (*ssh.ClientConfig, error) {
	if strings.TrimSpace(c.Username) == "" || !strings.HasPrefix(c.HostKey, "SHA256:") {
		return nil, errors.New("SSH credentials or host fingerprint missing")
	}
	var auth []ssh.AuthMethod
	if c.PrivateKey != "" {
		key, err := ssh.ParsePrivateKey([]byte(c.PrivateKey))
		if err != nil {
			return nil, errors.New("invalid or encrypted SSH private key")
		}
		auth = append(auth, ssh.PublicKeys(key))
	} else if c.Password != "" {
		auth = append(auth, ssh.Password(c.Password))
	}
	if len(auth) == 0 {
		return nil, errors.New("SSH authentication missing")
	}
	return &ssh.ClientConfig{User: c.Username, Auth: auth, Timeout: 30 * time.Second, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if ssh.FingerprintSHA256(key) != c.HostKey {
			return errors.New("SSH host fingerprint mismatch")
		}
		return nil
	}}, nil
}

func kindlyManagedDNSStart(raw []byte) int32 {
	var input managedDNSConfig
	if err := json.Unmarshal(raw, &input); err != nil {
		return -4
	}
	cfg, err := input.carrier()
	if err != nil {
		return -4
	}
	if input.BuiltIn {
		if _, err := panelControl(input.PhysicalInterface); err != nil || input.TunnelType != "socks5" || len(input.Resolvers) == 0 || len(input.Resolvers) > 4 {
			return -4
		}
	}
	if input.TunnelType == "ssh" {
		if _, err = input.sshConfig(); err != nil {
			return -4
		}
	}
	KindlyTurnStop()
	if !kindlyTurnCanStart() {
		return -5
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	kindlyTurnState.Lock()
	kindlyTurnState.generation++
	generation := kindlyTurnState.generation
	kindlyTurnState.cancel = cancel
	kindlyTurnState.done = done
	kindlyTurnState.running = true
	kindlyTurnState.lastError = ""
	kindlyTurnState.recovery = &transports.Status{Running: true, Stage: "starting", Transport: "dnstt"}
	kindlyTurnState.Unlock()
	report := func(status transports.Status) {
		kindlyTurnState.Lock()
		defer kindlyTurnState.Unlock()
		if generation == kindlyTurnState.generation {
			kindlyTurnState.recovery = &status
		}
	}
	go func() {
		defer close(done)
		err := runManagedDNS(ctx, cfg, input, report)
		if err != nil && ctx.Err() == nil {
			report(transports.Status{Stage: "failed", Transport: "dnstt", Code: "dns_or_ssh_connection_failed"})
		}
		// Never publish SSH errors containing credentials, endpoints or server banners.
		kindlyTurnFinish(generation, nil)
	}()
	return 0
}

func runManagedDNS(ctx context.Context, cfg transports.Config, input managedDNSConfig, report func(transports.Status)) error {
	if input.BuiltIn {
		return runBuiltInDNS(ctx, input, report)
	}
	if input.TunnelType == "socks5" {
		return transports.Run(ctx, cfg, report)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	clientConfig, err := input.sshConfig()
	if err != nil {
		return err
	}
	budget := transports.NewDNSQueryBudget(800)
	pool, err := transports.OpenStreamPool(ctx, input.sessions(), func(attempt context.Context, index int) (transports.PoolSession, error) {
		carrier, err := openManagedCarrier(attempt, input, *cfg.Profiles[0].DNS, budget, index)
		if err != nil {
			return nil, err
		}
		stream, err := carrier.Open(attempt)
		if err != nil {
			carrier.Close()
			return nil, err
		}
		conn, ok := stream.(net.Conn)
		if !ok {
			stream.Close()
			carrier.Close()
			return nil, errors.New("DNS stream lacks deadlines")
		}
		sshSession, err := openManagedSSHSession(attempt, conn, carrier, clientConfig)
		if err != nil {
			return nil, err
		}
		return sshSession, nil
	})
	if err != nil {
		return err
	}
	defer pool.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:9002")
	if err != nil {
		return err
	}
	defer listener.Close()
	closeListener := context.AfterFunc(ctx, func() { listener.Close() })
	defer closeListener()
	publish := func() {
		live := pool.LiveCount()
		stage := "authenticated"
		if live == 0 {
			stage = "reconnecting"
		}
		report(transports.Status{Running: true, Ready: live > 0, Stage: stage, Profile: "managed_dns", Transport: "dnstt-ssh", ConnectedStreams: live, RequestedStreams: input.sessions()})
	}
	publish()
	statusDone := make(chan struct{})
	defer func() { cancel(); <-statusDone }()
	go func() {
		defer close(statusDone)
		for {
			select {
			case <-ctx.Done():
				return
			case <-pool.Changes():
				if ctx.Err() == nil {
					publish()
				}
			}
		}
	}()
	var workers sync.WaitGroup
	defer func() { cancel(); listener.Close(); pool.Close(); workers.Wait() }()
	slots := make(chan struct{}, 32)
	for {
		local, err := listener.Accept()
		if err != nil {
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			local.Close()
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-slots }()
			defer local.Close()
			closeLocal := context.AfterFunc(ctx, func() { local.Close() })
			defer closeLocal()
			local.SetDeadline(time.Now().Add(30 * time.Second))
			target, err := managedSOCKSTarget(local)
			if err != nil {
				return
			}
			dialCtx, dialCancel := context.WithTimeout(ctx, 30*time.Second)
			remote, err := pool.Open(context.WithValue(dialCtx, managedSSHTarget{}, target))
			dialCancel()
			if err != nil {
				local.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
				return
			}
			defer remote.Close()
			if _, err = local.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
				return
			}
			local.SetDeadline(time.Time{})
			copied := make(chan struct{}, 1)
			go func() { io.Copy(remote, local); remote.Close(); copied <- struct{}{} }()
			io.Copy(local, remote)
			local.Close()
			<-copied
		}()
	}
}

// The listener is loopback-only and supports SOCKS5 CONNECT, matching SSH's TCP forwarding.
func managedSOCKSTarget(conn net.Conn) (string, error) {
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return "", err
	}
	if greeting[0] != 5 || greeting[1] == 0 {
		return "", errors.New("invalid SOCKS greeting")
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", err
	}
	supported := false
	for _, m := range methods {
		if m == 0 {
			supported = true
		}
	}
	if !supported {
		conn.Write([]byte{5, 255})
		return "", errors.New("SOCKS authentication unsupported")
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return "", err
	}
	var request [4]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil {
		return "", err
	}
	if request[0] != 5 || request[1] != 1 || request[2] != 0 {
		conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return "", errors.New("only CONNECT supported")
	}
	var host string
	switch request[3] {
	case 1, 4:
		n := 4
		if request[3] == 4 {
			n = 16
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return "", err
		}
		if n[0] == 0 {
			return "", errors.New("empty destination")
		}
		b := make([]byte, int(n[0]))
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		return "", errors.New("invalid SOCKS address")
	}
	var port [2]byte
	if _, err := io.ReadFull(conn, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(port[:]))), nil
}
