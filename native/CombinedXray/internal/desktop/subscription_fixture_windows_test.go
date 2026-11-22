package desktop

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

func TestWindowsSignedSubscriptionHTTPSRoundTrip(t *testing.T) {
	t.Setenv("TNDTUN_TEST_DATA", t.TempDir())
	c, err := NewController(io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, clientID, token := UUID(), UUID(), Nonce()
	keyID := "0000000000000000"
	var outage atomic.Bool
	service := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if outage.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var request struct{ Nonce string }
		if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&request) != nil || request.Nonce == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		settings := map[string]any{}
		_ = json.Unmarshal(Pack(DefaultState().Settings), &settings)
		settings["subscriptionSync"] = map[string]any{"enabled": true, "intervalMinutes": 15}
		raw := Pack(map[string]any{
			"format": "TnDtun-package", "schema_version": 1, "device_id": device,
			"client_id": clientID, "client_name": "Local Windows TLS fixture",
			"nonce": request.Nonce, "revision": 1, "status": "active",
			"issued_at": "2026-11-22T00:00:00Z", "sync_after_seconds": 60,
			"profiles": []any{}, "settings": settings, "subscription_code": "ABCD",
		})
		pkg := map[string]any{
			"algorithm": "Ed25519", "key_id": keyID,
			"payload":   base64.RawURLEncoding.EncodeToString(raw),
			"signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, raw)),
		}
		switch r.URL.Path {
		case "/v1/activate":
			_ = json.NewEncoder(w).Encode(map[string]any{"device_id": device, "token": token, "package": pkg})
		case "/v1/sync":
			if r.Header.Get("Authorization") != "Bearer "+token {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(pkg)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer service.Close()
	c.requestPanel = func(ctx context.Context, origin Trust, op string, body any, bearer string) ([]byte, error) {
		if origin.API != service.URL+"/v1" {
			t.Fatal("fixture request escaped the ephemeral HTTPS server")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin.API+"/"+op, bytes.NewReader(Pack(body)))
		if err != nil {
			return nil, err
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		reply, err := service.Client().Do(req)
		if err != nil {
			return nil, err
		}
		defer reply.Body.Close()
		if reply.StatusCode != http.StatusOK {
			return nil, PanelError(reply.StatusCode, "")
		}
		return io.ReadAll(reply.Body)
	}
	link := "tndtun://activate?api=" + url.QueryEscape(service.URL+"/v1") +
		"&code=ABCD&kid=" + keyID + "&key=" + base64.RawURLEncoding.EncodeToString(public)
	if err := c.Activate(link, true); err != nil {
		t.Fatal(err)
	}
	id := service.URL + "/v1#" + device
	if err := c.Sync(id); err != nil {
		t.Fatal(err)
	}
	before := c.s.Subscriptions[0]
	outage.Store(true)
	if err := c.Sync(id); err == nil {
		t.Fatal("expected HTTPS failure")
	}
	state, err := Load(c.path)
	if err != nil {
		t.Fatal(err)
	}
	sub := state.Subscriptions[0]
	if sub.Sync == 0 || sub.Sync != before.Sync || sub.NextSync-sub.Sync != 900 ||
		sub.Token != token || sub.ActivationCode != "ABCD" || sub.RetrySyncAt == 0 {
		t.Fatal("failed refresh changed the accepted subscription or dropped backoff")
	}
}
