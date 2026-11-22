package libXray

// The panel transport owns its own contexts, DNSTT sessions and HTTP clients.
// It never calls KindlyTurnStart/Stop, Xray, or installs a system route/DNS.
import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/KindlyVPN/foundation/transports"
	"kindlyvpn/native/internal/paneldnstt"
)

const panelEnvelopeLimit = 12 * 1024 * 1024

type panelRequest struct {
	ID          string   `json:"id"`
	API         string   `json:"api"`
	KeyID       string   `json:"key_id"`
	PublicKey   string   `json:"public_key"`
	Path        string   `json:"path"`
	Body        string   `json:"body"`
	Token       string   `json:"token"`
	Domain      string   `json:"domain"`
	DNSKey      string   `json:"dns_key"`
	Sessions    int      `json:"sessions"`
	Resolvers   []string `json:"resolvers"`
	Interface   string   `json:"interface"`
	PhysicalDNS []string `json:"physical_dns"`
	ForceDNS    bool     `json:"force_dns"`
	DirectOnly  bool     `json:"direct_only"`
	Budget      int      `json:"budget_seconds"`
}
type panelReply struct {
	Status    int    `json:"status"`
	Body      string `json:"body,omitempty"`
	Transport string `json:"transport,omitempty"`
	Resolver  string `json:"resolver,omitempty"`
	Error     string `json:"error,omitempty"`
}

var panelOperations = struct {
	sync.Mutex
	active    map[string]context.CancelFunc
	cancelled map[string]bool
}{active: make(map[string]context.CancelFunc), cancelled: make(map[string]bool)}

// KindlyPanelRequest is called on a Swift worker, with cancellation by ID.
// Result errors are fixed codes: no HTTP bodies, device tokens or native configs
// are ever sent to a logger or included in an exception message.
func KindlyPanelRequest(raw string) string {
	var request panelRequest
	if len(raw) > 32768 || json.Unmarshal([]byte(raw), &request) != nil {
		return panelReplyJSON(panelReply{Error: "invalid_request"})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 192*time.Second)
	defer cancel()
	panelOperations.Lock()
	if request.ID == "" || panelOperations.cancelled[request.ID] || panelOperations.active[request.ID] != nil {
		delete(panelOperations.cancelled, request.ID)
		panelOperations.Unlock()
		return panelReplyJSON(panelReply{Error: "cancelled"})
	}
	panelOperations.active[request.ID] = cancel
	panelOperations.Unlock()
	defer func() { panelOperations.Lock(); delete(panelOperations.active, request.ID); panelOperations.Unlock() }()
	reply := panelExchange(ctx, request)
	return panelReplyJSON(reply)
}
func KindlyPanelCancel(id string) {
	panelOperations.Lock()
	defer panelOperations.Unlock()
	if cancel := panelOperations.active[id]; cancel != nil {
		cancel()
		return
	}
	if len(panelOperations.cancelled) >= 64 {
		panelOperations.cancelled = make(map[string]bool)
	}
	panelOperations.cancelled[id] = true
}
func KindlyPanelActiveRequests() int32 {
	panelOperations.Lock()
	defer panelOperations.Unlock()
	return int32(len(panelOperations.active))
}
func panelReplyJSON(reply panelReply) string { data, _ := json.Marshal(reply); return string(data) }

func panelValidate(r panelRequest) (*url.URL, error) {
	u, err := url.Parse(r.API)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "/v1" || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return nil, errors.New("invalid API")
	}
	if u.Port() != "" {
		p, e := strconv.Atoi(u.Port())
		if e != nil || p < 1 || p > 65535 {
			return nil, errors.New("invalid port")
		}
	}
	if r.Path != "manifest" && r.Path != "activate" && r.Path != "sync" {
		return nil, errors.New("invalid endpoint")
	}
	if r.Path == "manifest" && (r.Token != "" || r.Body != "") {
		return nil, errors.New("manifest credentials")
	}
	if r.Sessions != 1 && r.Sessions != 2 && r.Sessions != 4 && r.Sessions != 8 {
		return nil, errors.New("invalid pool")
	}
	if r.ForceDNS && r.DirectOnly || len(r.Resolvers) > 4 || r.Interface == "" || strings.ContainsAny(r.Token, "\r\n") || len(r.Token) > 4096 || len(r.Body) > 16384 {
		return nil, errors.New("invalid request")
	}
	return u, nil
}

func panelExchange(parent context.Context, r panelRequest) panelReply {
	api, err := panelValidate(r)
	if err != nil {
		return panelReply{Error: "invalid_request"}
	}
	budget := r.Budget
	if budget <= 0 || budget > 192 {
		budget = 192
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(budget)*time.Second)
	defer cancel()
	// Ordinary API HTTPS may use an already working system VPN. Only the
	// fallback DNS carrier must bypass it and bind to the physical interface.
	direct := panelAPIHTTP(12 * time.Second)
	defer direct.CloseIdleConnections()
	return panelExchangeWithClient(ctx, r, api, direct)
}

func panelExchangeWithClient(ctx context.Context, r panelRequest, api *url.URL, direct *http.Client) panelReply {
	if !r.ForceDNS {
		status, body, err := panelHTTP(ctx, direct, r.API+"/"+r.Path, r.Body, r.Token)
		if err == nil {
			return panelReply{Status: status, Body: base64.StdEncoding.EncodeToString(body), Transport: "direct"}
		}
		if errors.Is(err, errPanelTooLarge) {
			return panelReply{Error: "response_too_large"}
		}
	}
	if ctx.Err() != nil {
		return panelReply{Error: panelContextError(ctx)}
	}
	// Swift may separate the phases to display the actual fallback state. This
	// never reclassifies an HTTP response as failure or starts a DNS session.
	if r.DirectOnly {
		return panelReply{Error: "direct_unavailable"}
	}
	key, err := hex.DecodeString(r.DNSKey)
	if err != nil || len(key) != 32 {
		return panelReply{Error: "invalid_request"}
	}
	dnsDeadline := time.Now().Add(180 * time.Second)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(dnsDeadline) {
		dnsDeadline = deadline
	}
	for _, resolver := range r.Resolvers {
		if ctx.Err() != nil {
			return panelReply{Error: "cancelled"}
		}
		if time.Until(dnsDeadline) < 90*time.Second {
			break
		}
		reply, err := panelThroughDNS(ctx, r, api, resolver, key, dnsDeadline)
		if err == nil {
			return reply
		}
		if errors.Is(err, errPanelTooLarge) {
			return panelReply{Error: "response_too_large"}
		}
		if errors.Is(err, errPanelManifest) {
			return panelReply{Error: "untrusted_manifest"}
		}
	}
	if ctx.Err() != nil {
		return panelReply{Error: panelContextError(ctx)}
	}
	return panelReply{Error: "dns_channel_unavailable"}
}

func panelContextError(ctx context.Context) string {
	if errors.Is(ctx.Err(), context.Canceled) {
		return "cancelled"
	}
	return "dns_channel_unavailable"
}

var errPanelTooLarge = errors.New("response too large")
var errPanelManifest = errors.New("manifest differs from pinned source")

func panelHTTP(ctx context.Context, client *http.Client, target, body, token string) (int, []byte, error) {
	method := "GET"
	var reader io.Reader
	if body != "" {
		method = "POST"
		reader = strings.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Accept", "application/json")
	if reader != nil {
		request.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	limit := panelEnvelopeLimit
	if response.StatusCode < 200 || response.StatusCode >= 300 || method == "GET" {
		limit = 16 * 1024
	}
	// net/http decompresses gzip before this limit. No redirect is ever followed.
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil {
		return 0, nil, err
	}
	if len(data) > limit {
		return 0, nil, errPanelTooLarge
	}
	return response.StatusCode, data, nil
}
func panelClient(transport *http.Transport, timeout time.Duration) *http.Client {
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func panelAPIHTTP(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	return panelClient(&http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 8 * time.Second, MaxResponseHeaderBytes: 32768, DisableKeepAlives: true,
		DialContext: dialer.DialContext}, timeout)
}

func panelThroughDNS(parent context.Context, r panelRequest, api *url.URL, resolver string, key []byte, deadline time.Time) (panelReply, error) {
	ctx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	readyDeadline := time.Now().Add(30 * time.Second)
	if spare := deadline.Add(-90 * time.Second); spare.Before(readyDeadline) {
		readyDeadline = spare
	}
	if !readyDeadline.After(time.Now()) {
		return panelReply{}, context.DeadlineExceeded
	}

	poolCtx, stopPool := context.WithCancel(ctx)
	queryBudget := paneldnstt.NewQueryBudget(400)
	defer stopPool()
	type poolResult struct {
		pool *transports.StreamPool
		err  error
	}
	result := make(chan poolResult, 1)
	go func() {
		pool, err := transports.OpenStreamPool(poolCtx, r.Sessions, func(attempt context.Context, _ int) (transports.PoolSession, error) {
			wire, addr, err := panelDNSWire(attempt, r.Interface, resolver)
			if err != nil {
				return nil, err
			}
			session, err := paneldnstt.Open(attempt, r.Domain, key, wire, addr, queryBudget)
			if err != nil {
				wire.Close()
				return nil, err
			}
			return session, nil
		})
		result <- poolResult{pool, err}
	}()
	timer := time.NewTimer(time.Until(readyDeadline))
	defer timer.Stop()
	var opened poolResult
	select {
	case opened = <-result:
	case <-timer.C:
		stopPool()
		opened = <-result
		if opened.pool != nil {
			opened.pool.Close()
		}
		return panelReply{}, context.DeadlineExceeded
	case <-ctx.Done():
		stopPool()
		opened = <-result
		if opened.pool != nil {
			opened.pool.Close()
		}
		return panelReply{}, ctx.Err()
	}
	if opened.err != nil {
		return panelReply{}, opened.err
	}
	pool := opened.pool
	defer pool.Close()

	port := api.Port()
	if port == "" {
		port = "443"
	}
	expected := net.JoinHostPort(api.Hostname(), port)
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 20 * time.Second,
		DisableKeepAlives: true, MaxResponseHeaderBytes: 32768,
		DialContext: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			if address != expected {
				return nil, errors.New("panel origin only")
			}
			stream, err := pool.Open(dialCtx)
			if err != nil {
				return nil, err
			}
			conn := newPanelConn(ctx, stream)
			handshakeDeadline := time.Now().Add(15 * time.Second)
			if d, ok := dialCtx.Deadline(); ok && d.Before(handshakeDeadline) {
				handshakeDeadline = d
			}
			conn.SetDeadline(handshakeDeadline)
			if err := panelSOCKS(conn, api.Hostname(), port); err != nil {
				conn.Close()
				return nil, err
			}
			conn.SetDeadline(time.Time{})
			return conn, nil
		}}
	client := panelClient(transport, 0)
	defer client.CloseIdleConnections()
	probeCtx, stop := context.WithTimeout(ctx, 15*time.Second)
	status, manifest, err := panelHTTP(probeCtx, client, r.API+"/manifest", "", "")
	stop()
	if err != nil {
		return panelReply{}, err
	}
	if status != 200 || !panelManifestMatches(manifest, r) {
		return panelReply{}, errPanelManifest
	}
	if time.Until(deadline) < 90*time.Second {
		return panelReply{}, context.DeadlineExceeded
	}
	status, body, err := panelHTTP(ctx, client, r.API+"/"+r.Path, r.Body, r.Token)
	if err != nil {
		return panelReply{}, err
	}
	return panelReply{Status: status, Body: base64.StdEncoding.EncodeToString(body), Transport: "dnstt", Resolver: resolver}, nil
}

func panelSOCKS(conn net.Conn, host, port string) error {
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	var accepted [2]byte
	if _, err := io.ReadFull(conn, accepted[:]); err != nil {
		return err
	}
	if accepted != [2]byte{5, 0} {
		return errors.New("SOCKS authentication failed")
	}
	request := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			request = append(request, 1)
			request = append(request, v4...)
		} else {
			request = append(request, 4)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) > 253 {
			return errors.New("invalid SOCKS hostname")
		}
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return err
	}
	request = append(request, byte(p>>8), byte(p))
	if _, err = conn.Write(request); err != nil {
		return err
	}
	var reply [4]byte
	if _, err = io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if reply[0] != 5 || reply[1] != 0 {
		return errors.New("SOCKS target unavailable")
	}
	size := 0
	switch reply[3] {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		var n [1]byte
		if _, err = io.ReadFull(conn, n[:]); err != nil {
			return err
		}
		size = int(n[0])
	default:
		return errors.New("invalid SOCKS reply")
	}
	_, err = io.CopyN(io.Discard, conn, int64(size+2))
	return err
}

type panelConn struct {
	io.ReadWriteCloser
	mu    sync.Mutex
	timer *time.Timer
	stop  func() bool
	once  sync.Once
}

func newPanelConn(ctx context.Context, stream io.ReadWriteCloser) *panelConn {
	c := &panelConn{ReadWriteCloser: stream}
	c.mu.Lock()
	c.stop = context.AfterFunc(ctx, func() { c.Close() })
	c.mu.Unlock()
	return c
}
func (c *panelConn) Close() error {
	var err error
	c.once.Do(func() {
		c.mu.Lock()
		if c.timer != nil {
			c.timer.Stop()
		}
		stop := c.stop
		c.mu.Unlock()
		if stop != nil {
			stop()
		}
		err = c.ReadWriteCloser.Close()
	})
	return err
}
func (c *panelConn) LocalAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c *panelConn) RemoteAddr() net.Addr { return c.LocalAddr() }
func (c *panelConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.timer != nil {
		c.timer.Stop()
	}
	if !t.IsZero() {
		c.timer = time.AfterFunc(time.Until(t), func() { c.Close() })
	}
	return nil
}
func (c *panelConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *panelConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

// Strict manifest parsing does not import trust; it only compares an existing pin.
func panelManifestMatches(raw []byte, r panelRequest) bool {
	if !utf8.Valid(raw) || len(raw) > 16384 {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var consume func(int) (any, error)
	consume = func(depth int) (any, error) {
		if depth > 32 {
			return nil, errPanelManifest
		}
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				m := map[string]any{}
				for decoder.More() {
					name, err := decoder.Token()
					if err != nil {
						return nil, err
					}
					key, ok := name.(string)
					if !ok {
						return nil, errPanelManifest
					}
					if _, exists := m[key]; exists {
						return nil, errPanelManifest
					}
					value, err := consume(depth + 1)
					if err != nil {
						return nil, err
					}
					m[key] = value
				}
				end, err := decoder.Token()
				if err != nil || end != json.Delim('}') {
					return nil, errPanelManifest
				}
				return m, nil
			case '[':
				var list []any
				for decoder.More() {
					value, err := consume(depth + 1)
					if err != nil {
						return nil, err
					}
					list = append(list, value)
				}
				end, err := decoder.Token()
				if err != nil || end != json.Delim(']') {
					return nil, errPanelManifest
				}
				return list, nil
			default:
				return nil, errPanelManifest
			}
		}
		return token, nil
	}
	result, err := consume(0)
	if err != nil {
		return false
	}
	if _, err = decoder.Token(); err != io.EOF {
		return false
	}
	m, ok := result.(map[string]any)
	if !ok {
		return false
	}
	return m["algorithm"] == "Ed25519" && m["key_id"] == r.KeyID && m["public_key"] == r.PublicKey && m["api_base"] == r.API
}
