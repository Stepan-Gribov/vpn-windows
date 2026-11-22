package libXray

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPanelHTTPDoesNotRedirectCredentials(t *testing.T) {
	var leaked bool
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer destination.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 307) }))
	defer source.Close()
	transport := source.Client().Transport.(*http.Transport).Clone()
	status, _, err := panelHTTP(context.Background(), panelClient(transport, time.Second), source.URL, "{}", "private-token")
	if err != nil || status != 307 || leaked {
		t.Fatalf("redirect: status=%d err=%v leak=%v", status, err, leaked)
	}
}
func TestPanelHTTPKeepsTLSVerification(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) }))
	defer server.Close()
	_, _, err := panelHTTP(context.Background(), panelClient(http.DefaultTransport.(*http.Transport).Clone(), time.Second), server.URL, "{}", "")
	if err == nil {
		t.Fatal("accepted untrusted TLS")
	}
}
func TestPanelHTTPDecompressionLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		z := gzip.NewWriter(w)
		defer z.Close()
		io.Copy(z, io.LimitReader(zeroReader{}, panelEnvelopeLimit+1))
	}))
	defer server.Close()
	_, _, err := panelHTTP(context.Background(), panelClient(http.DefaultTransport.(*http.Transport).Clone(), 5*time.Second), server.URL, "{}", "")
	if err != errPanelTooLarge {
		t.Fatalf("decompression limit: %v", err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }
func TestPanelManifestRejectsDuplicatesAndPinChange(t *testing.T) {
	r := panelRequest{API: "https://example.test/v1", KeyID: "a", PublicKey: "b"}
	good := `{"algorithm":"Ed25519","api_base":"https://example.test/v1","key_id":"a","public_key":"b"}`
	if !panelManifestMatches([]byte(good), r) {
		t.Fatal("valid manifest")
	}
	for _, bad := range []string{strings.Replace(good, `"b"`, `"c"`, 1), strings.Replace(good, `"key_id":"a"`, `"key_id":"a","key_id":"a"`, 1), good + `{}`} {
		if panelManifestMatches([]byte(bad), r) {
			t.Fatal("accepted bad manifest")
		}
	}
}
func TestPanelConnCancellationAndDeadlineRelease(t *testing.T) {
	for i := 0; i < 50; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		a, b := net.Pipe()
		conn := newPanelConn(ctx, a)
		done := make(chan struct{})
		go func() { defer close(done); conn.Read(make([]byte, 1)) }()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); cancel() }()
		go func() { defer wg.Done(); conn.SetDeadline(time.Now().Add(time.Millisecond)); conn.Close() }()
		wg.Wait()
		b.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("stream leaked")
		}
	}
}
func TestPanelPrecancelDoesNotStartTransport(t *testing.T) {
	KindlyPanelCancel("pre-cancel")
	var result panelReply
	json.Unmarshal([]byte(KindlyPanelRequest(`{"id":"pre-cancel"}`)), &result)
	if result.Error != "cancelled" || KindlyPanelActiveRequests() != 0 {
		t.Fatal("cancelled operation leaked")
	}
}
