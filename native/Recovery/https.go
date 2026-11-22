package transports

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/KindlyVPN/foundation/transports/bootstrap"
	"github.com/coder/websocket"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/noise"
)

type httpsSession struct {
	*smux.Session
	close func()
}

func (s *httpsSession) Open(ctx context.Context) (io.ReadWriteCloser, error) {
	return openMuxStream(ctx, s.Session)
}
func (s *httpsSession) Done() <-chan struct{} { return s.CloseChan() }
func (s *httpsSession) Close() error          { s.close(); return nil }

func openHTTPS(ctx context.Context, cfg HTTPSConfig, resolvers []string) (session, error) {
	transport := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, Resolver: bootstrap.Resolver(resolvers)}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return dialHTTPS(ctx, cfg, &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }})
}

func dialHTTPS(ctx context.Context, cfg HTTPSConfig, client *http.Client) (session, error) {
	attempt, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	ws, response, err := websocket.Dial(attempt, cfg.URL, &websocket.DialOptions{HTTPClient: client, Subprotocols: []string{"kindly-noise-v1"}})
	if response != nil && err != nil {
		response.Body.Close()
	}
	if err != nil {
		return nil, errors.New("HTTPS relay connection failed")
	}
	if ws.Subprotocol() != "kindly-noise-v1" {
		ws.CloseNow()
		return nil, errors.New("HTTPS relay protocol mismatch")
	}
	ws.SetReadLimit(128 * 1024)
	conn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	key, _ := hex.DecodeString(cfg.PublicKey)
	rw, err := noise.NewClient(conn, key)
	if err != nil {
		conn.Close()
		return nil, errors.New("HTTPS relay end-to-end authentication failed")
	}
	conn.SetDeadline(time.Time{})
	smuxCfg := smux.DefaultConfig()
	smuxCfg.Version = 2
	smuxCfg.MaxReceiveBuffer = 1024 * 1024
	smuxCfg.KeepAliveTimeout = 45 * time.Second
	smuxSession, err := smux.Client(rw, smuxCfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &httpsSession{Session: smuxSession, close: func() { smuxSession.Close(); conn.Close(); client.CloseIdleConnections() }}, nil
}

// RelayHandler terminates only the carrier connection. Noise protects the payload
// across an HTTPS edge that terminates outer TLS. Every stream is sent to one fixed
// loopback authenticated VLESS inbound; clients cannot choose another destination.
func RelayHandler(privateKey []byte, target string) (http.Handler, error) {
	if len(privateKey) != 32 || loopbackAddress(target, false) != nil {
		return nil, errors.New("relay requires a private key and a fixed loopback inbound")
	}
	key := append([]byte(nil), privateKey...)
	sessions := make(chan struct{}, 32)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		select {
		case sessions <- struct{}{}:
			defer func() { <-sessions }()
		default:
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"kindly-noise-v1"}})
		if err != nil {
			return
		}
		defer ws.CloseNow()
		if ws.Subprotocol() != "kindly-noise-v1" {
			return
		}
		ws.SetReadLimit(128 * 1024)
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		conn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		rw, err := noise.NewServer(conn, key)
		if err != nil {
			return
		}
		conn.SetDeadline(time.Time{})
		cfg := smux.DefaultConfig()
		cfg.Version = 2
		cfg.MaxReceiveBuffer = 1024 * 1024
		cfg.KeepAliveTimeout = 45 * time.Second
		session, err := smux.Server(rw, cfg)
		if err != nil {
			return
		}
		defer session.Close()
		var wg sync.WaitGroup
		defer func() { cancel(); wg.Wait() }()
		limit := make(chan struct{}, 16)
		for {
			stream, err := session.AcceptStream()
			if err != nil {
				return
			}
			select {
			case limit <- struct{}{}:
			default:
				stream.Close()
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-limit }()
				defer stream.Close()
				remote, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", target)
				if err != nil {
					return
				}
				defer remote.Close()
				copyStream(ctx, stream, remote)
			}()
		}
	}), nil
}
