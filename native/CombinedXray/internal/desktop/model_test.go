package desktop

import (
	"bytes"
	"compress/zlib"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestStrictRejectsAmbiguousJSON(t *testing.T) {
	for _, s := range []string{`{"a":1,"a":2}`, `{} {}`, strings.Repeat("[", 70) + strings.Repeat("]", 70)} {
		var v any
		if Strict([]byte(s), &v, 4096) == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}
func testINI() string {
	k := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	p := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	return "[Interface]\nPrivateKey=" + k + "\nAddress=10.77.0.2/32\nJc=4\nS3=0\nRandomTrailers=on\n[Peer]\nPublicKey=" + p + "\nEndpoint=127.0.0.1:23000\nAllowedIPs=0.0.0.0/0\n"
}
func TestAmneziaQtCompressedImportAndBounds(t *testing.T) {
	cfg := map[string]any{"description": "Fixture", "containers": []any{map[string]any{"container": "amnezia-awg", "awg": map[string]any{"last_config": map[string]any{"config": testINI()}}}}}
	raw := Pack(cfg)
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, uint32(len(raw)))
	z := zlib.NewWriter(&b)
	z.Write(raw)
	z.Close()
	v, _, name, e := Amnezia("vpn://"+base64.RawURLEncoding.EncodeToString(b.Bytes()), 0)
	if e != nil || name != "Fixture" || !strings.Contains(v["uapi"].(string), "random_trailers=true") {
		t.Fatalf("import: %v", e)
	}
	bad := append([]byte{}, b.Bytes()...)
	binary.BigEndian.PutUint32(bad[:4], 3<<20)
	if _, _, _, e := Amnezia("vpn://"+base64.RawURLEncoding.EncodeToString(bad), 0); e == nil {
		t.Fatal("unbounded decompression")
	}
	if _, e := parseINI(strings.Replace(testINI(), "Jc=4", "PostUp=execute", 1)); e == nil {
		t.Fatal("hook accepted")
	}
}
func TestSplitModesPreserveListsAndDNSPriority(t *testing.T) {
	s := DefaultState().Settings
	s.Split = Split{Mode: "tunnelSelected", Bypass: []Entry{{Address: "example.org"}}, Tunnel: []Entry{{Address: "example.com", Networks: []string{"203.0.113.4/24", "2001:db8::1/32"}}}}
	if e := s.Validate(); e != nil {
		t.Fatal(e)
	}
	if s.Split.Tunnel[0].Networks[0] != "203.0.113.0/24" {
		t.Fatal("CIDR not masked")
	}
	p := Builtin()
	c, e := BuildConfig(p, s, "Wi-Fi", 12345, 12346, true)
	if e != nil {
		t.Fatal(e)
	}
	raw := string(Pack(c))
	for _, want := range []string{"198.18.0.2", "domain:example.com", "tcp+local://127.0.0.1:12345", "kindly-dns-query", "::/0"} {
		if !strings.Contains(raw, want) {
			t.Fatal(want)
		}
	}
	if len(s.Split.Bypass) != 1 {
		t.Fatal("lost inactive list")
	}
	s.Split.Mode = "bypassSelected"
	c, e = BuildConfig(p, s, "Wi-Fi", 12345, 12346, true)
	if e != nil || !strings.Contains(string(Pack(c)), "domain:example.org") {
		t.Fatal("bypass")
	}
}
func TestPortableMacBackupSSHFields(t *testing.T) {
	s := DefaultState()
	p := Builtin()
	p.ID = UUID()
	p.DNS.TunnelType = "ssh"
	p.DNS.Username = "fixture"
	p.DNS.Password = "not-real"
	p.DNS.HostKey = "SHA256:fixture"
	s.Profiles = []Profile{p}
	if e := s.Validate(); e != nil {
		t.Fatal(e)
	}
	raw := Pack(s)
	for _, field := range []string{"appVersion", "appBuild", "createdAt"} {
		if !bytes.Contains(raw, []byte(`"`+field+`"`)) {
			t.Fatal("missing Mac backup field:", field)
		}
	}
	var next State
	if Strict(raw, &next, 20<<20) != nil || next.Validate() != nil || next.Profiles[0].DNS.Username != "fixture" {
		t.Fatal("portable SSH fields")
	}
	if !bytes.Contains(raw, []byte(`"sshUsername"`)) {
		t.Fatal("Mac field names")
	}
	next.Profiles[0].ID = ""
	if next.Validate() == nil {
		t.Fatal("missing ID accepted")
	}
}

func TestXrayImportUsesStandaloneConnectionAndAppRouting(t *testing.T) {
	raw := `{"outbounds":[{"protocol":"freedom","tag":"direct"},{"protocol":"vless","tag":"foreign","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"11111111-1111-4111-8111-111111111111","encryption":"none"}]}]}}],"routing":{"rules":[]},"inbounds":[{"port":99}]}`
	_, custom, _, e := Amnezia(raw, 0)
	if e != nil {
		t.Fatal(e)
	}
	list := custom["outbounds"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["tag"] != "proxy" || custom["inbounds"] != nil {
		t.Fatal("foreign routing imported")
	}
}
func TestActivationRejectsDuplicateTrustAndUnknownSchemes(t *testing.T) {
	for _, v := range []string{"AB12", "tndtun://activate?code=ABCD&code=EFGH", "http://example.com", "tndtun://activate?api=http://evil/v1&code=ABCD&kid=0000000000000000&key=x"} {
		if _, _, e := ParseActivation(v); e == nil {
			t.Fatal("accepted invalid activation")
		}
	}
	_, s, e := ParseActivation("a-b c d")
	if e != nil || s != "ABCD" {
		t.Fatal(e)
	}
}
func TestSignedPackageNonceDeviceRevisionAndTampering(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	trust := Bootstrap()
	trust.Key = base64.RawURLEncoding.EncodeToString(pub)
	device, client := UUID(), UUID()
	nonce := Nonce()
	payload := map[string]any{"format": "TnDtun-package", "schema_version": 1, "nonce": nonce, "device_id": device, "client_id": client, "client_name": "Fixture", "revision": 2, "status": "active", "expires_at": nil, "issued_at": time.Now().UTC().Format(time.RFC3339), "sync_after_seconds": 30, "profiles": []any{}, "settings": DefaultState().Settings}
	sign := func(p map[string]any) []byte {
		b := Pack(p)
		return Pack(map[string]any{"algorithm": "Ed25519", "key_id": trust.KeyID, "payload": base64.RawURLEncoding.EncodeToString(b), "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, b))})
	}
	raw := sign(payload)
	sub, _, _, e := VerifyPackage(raw, trust, nonce, device, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = VerifyPackage(raw, trust, "wrong", device, nil); e == nil {
		t.Fatal("wrong nonce")
	}
	if _, _, _, e = VerifyPackage(raw, trust, nonce, UUID(), nil); e == nil {
		t.Fatal("wrong device")
	}
	sub.Revision = 3
	if _, _, _, e = VerifyPackage(raw, trust, nonce, device, &sub); e == nil {
		t.Fatal("rollback")
	}
	var envelope map[string]any
	json.Unmarshal(raw, &envelope)
	envelope["payload"] = base64.RawURLEncoding.EncodeToString([]byte(`{"revision":999}`))
	if _, _, _, e = VerifyPackage(Pack(envelope), trust, nonce, device, nil); e == nil {
		t.Fatal("tampering")
	}
}
