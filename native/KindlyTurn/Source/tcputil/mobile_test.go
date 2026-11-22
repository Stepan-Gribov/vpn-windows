package tcputil

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

func TestMobileSmuxRemainsCompatibleWithDefaultServerUnderBackpressure(t *testing.T) {
	left, right := net.Pipe()
	client, err := smux.Client(left, MobileSmuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := smux.Server(right, DefaultSmuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	stream, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	payload := bytes.Repeat([]byte("mobile-TURN-payload"), 100000)
	result := make(chan error, 1)
	go func() {
		peer, err := server.AcceptStream()
		if err != nil {
			result <- err
			return
		}
		defer peer.Close()
		_, err = io.Copy(peer, peer)
		result <- err
	}()
	writeDone := make(chan error, 1)
	go func() { _, err := stream.Write(payload); writeDone <- err }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("mobile buffers corrupted bulk payload")
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if MobileSmuxConfig().Version != DefaultSmuxConfig().Version {
		t.Fatal("changed wire protocol")
	}
}
