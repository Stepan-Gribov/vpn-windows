// SPDX-FileCopyrightText: 2026 KindlyVPN contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package clientcore

import "testing"

func TestNormalizeMAXTURNURL(t *testing.T) {
	t.Parallel()

	got, err := normalizeMAXTURNURL([]string{
		"stun:155.212.205.1:19302",
		"turn:155.212.205.3:19302?transport=tcp",
		"turn:155.212.205.2:19302?transport=udp",
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if got != "155.212.205.2:19302" {
		t.Fatalf("unexpected address %q", got)
	}
}

func TestNormalizeMAXTURNURLIPv6(t *testing.T) {
	t.Parallel()

	got, err := normalizeMAXTURNURL([]string{"turn:[2001:db8::1]:443?transport=tcp"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if got != "[2001:db8::1]:443" {
		t.Fatalf("unexpected address %q", got)
	}
}

func TestNormalizeMAXTURNURLRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	if _, err := normalizeMAXTURNURL([]string{"stun:example.com:3478", "turn:missing-port"}, true); err == nil {
		t.Fatal("expected invalid TURN URLs to fail")
	}
	if _, err := normalizeMAXTURNURL([]string{"turn:example.com:3478?transport=udp"}, false); err == nil {
		t.Fatal("expected a UDP-only TURN URL to fail TCP selection")
	}
}

func TestIsDecimalID(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"1", "1234567890"} {
		if !isDecimalID(value) {
			t.Fatalf("expected %q to be valid", value)
		}
	}
	for _, value := range []string{"", "-1", "12 34", "user"} {
		if isDecimalID(value) {
			t.Fatalf("expected %q to be invalid", value)
		}
	}
}
