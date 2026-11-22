package desktop

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestDPAPIAtomicStorageAndCorruptionPreservation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.bin")
	s := DefaultState()
	s.Profiles = []Profile{Builtin()}
	s.Profiles[0].ID = UUID()
	s.Profiles[0].DNS.Password = "private-fixture-sentinel"
	s.Subscriptions = []Subscription{{ID: "fixture", ActivationCode: "0042"}}
	if e := Save(path, s); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(path)
	if bytes.Contains(b, []byte("private-fixture-sentinel")) {
		t.Fatal("plaintext key on disk")
	}
	next, e := Load(path)
	if e != nil || next.Installation != s.Installation {
		t.Fatal(e)
	}
	if len(next.Subscriptions) != 1 || next.Subscriptions[0].ActivationCode != "0042" {
		t.Fatal("subscription code changed after reopening protected storage")
	}
	b[3] ^= 128
	os.WriteFile(path, b, 0600)
	if _, e = Load(path); e == nil {
		t.Fatal("corruption accepted")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(b, after) {
		t.Fatal("corrupt state overwritten")
	}
}
