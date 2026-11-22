package desktop

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestSignedSubscriptionSyncPolicy(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := Trust{API: "https://example.invalid/v1", KeyID: "0000000000000000", Key: base64.RawURLEncoding.EncodeToString(pub)}
	device, client, nonce := UUID(), UUID(), Nonce()
	payload := map[string]any{
		"format": "TnDtun-package", "schema_version": 1, "device_id": device,
		"client_id": client, "client_name": "Fixture", "nonce": nonce, "revision": 1,
		"status": "active", "issued_at": time.Now().UTC().Format(time.RFC3339),
		"expires_at": nil, "sync_after_seconds": 60, "profiles": []Profile{},
	}
	now := time.Unix(1_800_000_000, 0)
	cases := []struct {
		name   string
		policy string
		valid  bool
		auto   bool
		dueIn  time.Duration
	}{
		{"legacy missing field", "", true, false, 0},
		{"disabled", `{"enabled":false,"intervalMinutes":15}`, true, false, 0},
		{"minimum", `{"enabled":true,"intervalMinutes":15}`, true, true, 15 * time.Minute},
		{"maximum", `{"enabled":true,"intervalMinutes":1440}`, true, true, 24 * time.Hour},
		{"too short", `{"enabled":true,"intervalMinutes":14}`, false, false, 0},
		{"too long", `{"enabled":true,"intervalMinutes":1441}`, false, false, 0},
		{"fraction", `{"enabled":true,"intervalMinutes":15.5}`, false, false, 0},
		{"string boolean", `{"enabled":"true","intervalMinutes":15}`, false, false, 0},
		{"missing enabled", `{"intervalMinutes":15}`, false, false, 0},
		{"null", "null", false, false, 0},
		{"extra field", `{"enabled":true,"intervalMinutes":15,"extra":1}`, false, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var settings map[string]json.RawMessage
			if err := json.Unmarshal(Pack(DefaultState().Settings), &settings); err != nil {
				t.Fatal(err)
			}
			if tc.policy != "" {
				settings["subscriptionSync"] = json.RawMessage(tc.policy)
			}
			payload["settings"] = settings
			raw := Pack(payload)
			signed := Pack(map[string]any{
				"algorithm": "Ed25519", "key_id": trust.KeyID,
				"payload":   base64.RawURLEncoding.EncodeToString(raw),
				"signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, raw)),
			})
			sub, _, _, err := VerifyPackage(signed, trust, nonce, device, nil)
			if (err == nil) != tc.valid {
				t.Fatalf("signature/package validation: %v", err)
			}
			if !tc.valid {
				return
			}
			if sub.Sync != 0 {
				t.Fatal("verifying a package must not record a successful application")
			}
			sub.recordSyncSuccess(now)
			if sub.Sync != now.Unix() || sub.automaticSyncEnabled() != tc.auto {
				t.Fatal("unexpected persisted success or policy")
			}
			if !tc.auto {
				if sub.NextSync != 0 || sub.syncDue(now.Add(48*time.Hour)) {
					t.Fatal("legacy and disabled subscriptions must remain manual")
				}
				return
			}
			due := now.Add(tc.dueIn)
			if sub.syncDue(due.Add(-time.Second)) || !sub.syncDue(due) {
				t.Fatal("wrong scheduled deadline")
			}
			sub.postponeFailedSync(due)
			if sub.Sync != now.Unix() || sub.NextSync != due.Unix() ||
				sub.syncDue(due) || !sub.syncDue(due.Add(15*time.Minute)) {
				t.Fatal("failed refresh changed the success date or did not back off")
			}
			sub.recordSyncSuccess(due.Add(15 * time.Minute))
			if sub.RetrySyncAt != 0 {
				t.Fatal("successful refresh did not clear backoff")
			}
		})
	}
}

func TestBundledOriginsRequireMatchingSigningIdentity(t *testing.T) {
	primary := Bootstrap()
	origins := trustedPanelOrigins(primary)
	if len(origins) < 2 {
		t.Fatal("expected bundled Windows HTTPS failover")
	}
	alternate := origins[1]
	if !samePanelService(primary, alternate) || trustedPanelOrigins(alternate)[0].API != primary.API {
		t.Fatal("existing alternate records must retain access to trusted origins")
	}
	foreign := alternate
	foreign.API = "https://example.invalid/v1"
	if samePanelService(primary, foreign) || len(trustedPanelOrigins(foreign)) != 1 {
		t.Fatal("arbitrary origins must not receive bundled credentials")
	}
	foreign = alternate
	foreign.KeyID = "0000000000000000"
	if foreign.KeyID == alternate.KeyID {
		foreign.KeyID = "1111111111111111"
	}
	if samePanelService(primary, foreign) {
		t.Fatal("untrusted signing identity")
	}
}
