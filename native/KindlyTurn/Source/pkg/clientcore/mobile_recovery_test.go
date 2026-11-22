package clientcore

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestConnectionCleanupCancelsAndClosesLateResourcesOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	add, cleanup := newConnectionCleanup(ctx)
	var closed atomic.Int32
	add(func() { closed.Add(1) })
	cancel()
	cleanup()
	cleanup()
	add(func() { closed.Add(1) })
	if got := closed.Load(); got != 2 {
		t.Fatalf("closed %d resources, want 2", got)
	}
}

func TestCancelInterruptsTURNAllocation(t *testing.T) {
	// The socket accepts outbound STUN but never answers. Stop must close the
	// allocation while it is pending, instead of leaving old lanes behind.
	blackhole, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tp := &turnParams{udp: true, mobile: true, getCreds: func(context.Context, string, int) (string, string, string, error) {
		return "user", "password", blackhole.LocalAddr().String(), nil
	}}
	finished := make(chan error, 1)
	go func() {
		_, cleanup, err := createSmuxSession(ctx, tp, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, 0)
		if cleanup != nil {
			cleanup()
		}
		finished <- err
	}()
	buf := make([]byte, 1500)
	_ = blackhole.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := blackhole.ReadFrom(buf); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("cancelled allocation succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled TURN allocation still running")
	}
}

func TestBondReordersFramesPreservesBytesAndIgnoresDuplicates(t *testing.T) {
	local, application := net.Pipe()
	defer local.Close()
	defer application.Close()
	frames := make(chan bondFrame, 5)
	frames <- bondFrame{typ: bondFrameData, seq: 1, data: []byte("world")}
	frames <- bondFrame{typ: bondFrameData, seq: 1, data: []byte("duplicate")}
	frames <- bondFrame{typ: bondFrameData, seq: 0, data: []byte("hello ")}
	frames <- bondFrame{typ: bondFrameData, seq: 0, data: []byte("old duplicate")}
	frames <- bondFrame{typ: bondFrameFIN, seq: 2}
	done := make(chan struct{})
	go func() { copyBondToTCP(context.Background(), 1, local, frames); close(done) }()
	_ = application.SetReadDeadline(time.Now().Add(time.Second))
	data := make([]byte, 11)
	if _, err := io.ReadFull(application, data); err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello world" {
		t.Fatalf("reordered payload %q", data)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("FIN did not finish download")
	}
	if used := bondPendingBytes.Load(); used != 0 {
		t.Fatalf("pending budget leaked: %d", used)
	}
}

func TestMissingBondLaneCannotGrowReorderMemoryWithoutBound(t *testing.T) {
	local, application := net.Pipe()
	defer local.Close()
	defer application.Close()
	frames := make(chan bondFrame, 40)
	for seq := uint64(1); seq <= 40; seq++ {
		frames <- bondFrame{typ: bondFrameData, seq: seq, data: make([]byte, bondMaxChunk)}
	}
	done := make(chan struct{})
	go func() { copyBondToTCP(context.Background(), 2, local, frames); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("missing lane kept growing/stalled")
	}
	if used := bondPendingBytes.Load(); used != 0 {
		t.Fatalf("pending budget leaked after failure: %d", used)
	}
}
