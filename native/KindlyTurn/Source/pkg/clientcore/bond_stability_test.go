package clientcore

import (
	"bytes"
	"context"
	"github.com/xtaci/smux"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// A successful write to a lane is not a delivery acknowledgement. Losing that
// lane must unblock the affected local TCP even if another lane is still alive.
func TestBondLaneLossStopsAffectedConnection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var candidates []*pooledSession
	var peers []*smux.Session
	for i := 0; i < 2; i++ {
		a, b := net.Pipe()
		c, err := smux.Client(a, nil)
		if err != nil {
			t.Fatal(err)
		}
		s, err := smux.Server(b, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		defer s.Close()
		candidates = append(candidates, &pooledSession{id: i, sess: c})
		peers = append(peers, s)
	}
	local, app := net.Pipe()
	defer app.Close()
	done := make(chan struct{})
	go func() { defer close(done); handleBondedTCP(ctx, local, 1, candidates) }()
	var streams []*smux.Stream
	for _, p := range peers {
		p.SetDeadline(time.Now().Add(time.Second))
		s, err := p.AcceptStream()
		if err != nil {
			t.Fatal(err)
		}
		s.SetReadDeadline(time.Now().Add(time.Second))
		if _, err = io.ReadFull(s, make([]byte, 17)); err != nil {
			t.Fatal(err)
		}
		streams = append(streams, s)
	}
	streams[0].Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("lost bond lane left TCP hanging while another lane survived")
	}
	if candidates[1].sess.IsClosed() {
		t.Fatal("unrelated healthy transport session was closed")
	}
}

func TestBondDownloadReordersAndIgnoresDuplicate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	local, app := net.Pipe()
	defer local.Close()
	defer app.Close()
	frames := make(chan bondFrame, 5)
	frames <- bondFrame{typ: bondFrameData, seq: 1, data: []byte("world")}
	frames <- bondFrame{typ: bondFrameData, seq: 1, data: []byte("world")}
	frames <- bondFrame{typ: bondFrameData, seq: 0, data: []byte("hello ")}
	frames <- bondFrame{typ: bondFrameFIN, seq: 2}
	done := make(chan struct{})
	go func() { defer close(done); copyBondToTCP(ctx, 2, local, frames) }()
	app.SetReadDeadline(time.Now().Add(time.Second))
	body := make([]byte, 11)
	if _, err := io.ReadFull(app, body); err != nil || string(body) != "hello world" {
		t.Fatalf("reassembly: %q %v", body, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("FIN did not finish download")
	}
}

func TestBondMissingSequenceHasDeadlineAndMemoryBound(t *testing.T) {
	for _, overflow := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		local, app := net.Pipe()
		frames := make(chan bondFrame, 300)
		frames <- bondFrame{typ: bondFrameData, seq: 1, data: []byte("gap")}
		if overflow {
			for i := 2; i <= 258; i++ {
				frames <- bondFrame{typ: bondFrameData, seq: uint64(i), data: []byte("pending")}
			}
		}
		done := make(chan struct{})
		go func() { defer close(done); copyBondToTCP(ctx, 3, local, frames) }()
		limit := 9 * time.Second
		if overflow {
			limit = time.Second
		}
		select {
		case <-done:
		case <-time.After(limit):
			cancel()
			t.Fatal("missing sequence retained an unbounded connection")
		}
		cancel()
		local.Close()
		app.Close()
	}
}

func TestBondUploadHalfCloseStillReceivesResponse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, b := net.Pipe()
	client, err := smux.Client(a, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := smux.Server(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, e := listener.Accept()
		if e == nil {
			handleBondedTCP(ctx, conn, 9, []*pooledSession{{id: 0, sess: client}})
		}
	}()
	payload := bytes.Repeat([]byte("bond-final-response"), 65536)
	serverDone := make(chan error, 1)
	go func() {
		stream, e := server.AcceptStream()
		if e != nil {
			serverDone <- e
			return
		}
		defer stream.Close()
		stream.SetDeadline(time.Now().Add(8 * time.Second))
		_, e = io.ReadFull(stream, make([]byte, 17))
		if e != nil {
			serverDone <- e
			return
		}
		for {
			f, e := readBondFrame(stream)
			if e != nil {
				serverDone <- e
				return
			}
			if f.typ == bondFrameFIN {
				break
			}
		}
		var seq uint64
		for offset := 0; offset < len(payload); offset += bondMaxChunk {
			end := offset + bondMaxChunk
			if end > len(payload) {
				end = len(payload)
			}
			if e = writeBondFrame(stream, bondFrameData, seq, payload[offset:end]); e != nil {
				break
			}
			seq++
		}
		if e == nil {
			e = writeBondFrame(stream, bondFrameFIN, seq, nil)
		}
		serverDone <- e
	}()
	app, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	app.SetDeadline(time.Now().Add(8 * time.Second))
	app.Write([]byte("request"))
	app.(*net.TCPConn).CloseWrite()
	body, err := io.ReadAll(app)
	if err != nil || !bytes.Equal(body, payload) {
		t.Fatalf("half-close truncated reply: %d/%d bytes, %v", len(body), len(payload), err)
	}
	if err = <-serverDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("half-closed connection did not finish")
	}
}

func TestBondLaneCloseDrainsQueuedFinalFrames(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	local, app := net.Pipe()
	defer local.Close()
	defer app.Close()
	frames := make(chan bondFrame, 16)
	payload := bytes.Repeat([]byte("queued-final-body"), 512)
	done := make(chan struct{})
	go func() { copyBondToTCP(ctx, 1, local, frames); close(done) }()
	go func() {
		frames <- bondFrame{typ: bondLaneClosed}
		time.Sleep(20 * time.Millisecond)
		frames <- bondFrame{typ: bondFrameData, seq: 0, data: payload}
		frames <- bondFrame{typ: bondFrameFIN, seq: 1}
		close(frames)
	}()
	app.SetDeadline(time.Now().Add(2 * time.Second))
	data := make([]byte, len(payload))
	if _, err := io.ReadFull(app, data); err != nil || !bytes.Equal(data, payload) {
		t.Fatal("queued final response truncated", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("FIN not drained")
	}
	if used := bondPendingBytes.Load(); used != 0 {
		t.Fatal("pending budget leak", used)
	}
}

// A quiet, healthy TCP connection must not be mistaken for a sequence gap.
func TestBondIdleWithoutGapIsNotExpired(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	local, app := net.Pipe()
	defer local.Close()
	defer app.Close()
	frames := make(chan bondFrame, 1)
	done := make(chan struct{})
	go func() { copyBondToTCP(ctx, 1, local, frames); close(done) }()
	select {
	case <-done:
		t.Fatal("idle connection expired")
	case <-time.After(bondGapTimeout + 100*time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle connection did not cancel")
	}
}

type stalledBondWriter struct {
	net.Conn
	stall  atomic.Bool
	closed chan struct{}
}

func (c *stalledBondWriter) Write(data []byte) (int, error) {
	if c.stall.Load() {
		<-c.closed
		return 0, io.ErrClosedPipe
	}
	return c.Conn.Write(data)
}

func TestBondStalledWriteClosesLocalTCPWithoutReplay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var candidates []*pooledSession
	var peers []*smux.Session
	var streams []*smux.Stream
	var stalled *stalledBondWriter
	for i := 0; i < 2; i++ {
		a, b := net.Pipe()
		var conn net.Conn = a
		if i == 0 {
			stalled = &stalledBondWriter{Conn: a, closed: make(chan struct{})}
			conn = stalled
			defer func() {
				select {
				case <-stalled.closed:
				default:
					close(stalled.closed)
				}
			}()
		}
		c, err := smux.Client(conn, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		peer, err := smux.Server(b, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Close()
		candidates = append(candidates, &pooledSession{id: i, sess: c})
		peers = append(peers, peer)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err == nil {
			handleBondedTCP(ctx, conn, 1, candidates)
		}
	}()
	app, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	for _, peer := range peers {
		peer.SetDeadline(time.Now().Add(time.Second))
		stream, err := peer.AcceptStream()
		if err != nil {
			t.Fatal(err)
		}
		stream.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := io.ReadFull(stream, make([]byte, 17)); err != nil {
			t.Fatal(err)
		}
		streams = append(streams, stream)
	}
	stalled.stall.Store(true)
	app.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := app.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	n, err := app.Read(buf)
	if err == nil || n != 0 {
		t.Fatal("damaged TCP was not closed")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("bond write deadline did not release the application TCP")
	}
	streams[1].SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	n, _ = streams[1].Read(buf)
	if n != 0 {
		t.Fatal("failed frame replayed on another lane")
	}
	if candidates[1].sess.IsClosed() {
		t.Fatal("healthy smux session closed")
	}
	// Unblock the deliberately wedged fixture writer after proving that the
	// local TCP was released, so smux's bounded Close can finish too.
	close(stalled.closed)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("bond cleanup did not finish")
	}
}
