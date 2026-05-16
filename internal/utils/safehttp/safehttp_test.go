// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package safehttp

import (
	"errors"
	"net"
	"testing"
)

func TestCheckIP(t *testing.T) {
	tests := []struct {
		ip            string
		allowPrivate  bool
		allowLoopback bool
		wantBlocked   bool
		why           string
	}{
		// Always-denied (loopback denied unless AllowLoopback)
		{"127.0.0.1", true, false, true, "loopback denied by default"},
		{"127.0.0.1", false, false, true, "loopback denied by default"},
		{"127.0.0.1", false, true, false, "loopback allowed for tests"},
		{"::1", true, false, true, "loopback v6 denied by default"},
		{"::1", false, true, false, "loopback v6 allowed for tests"},
		{"0.0.0.0", true, false, true, "unspecified"},
		{"::", true, false, true, "unspecified v6"},
		{"169.254.169.254", true, true, true, "AWS/GCE IMDS always blocked"},
		{"169.254.169.254", false, false, true, "AWS/GCE IMDS always blocked"},
		{"169.254.1.1", true, true, true, "link-local v4 always blocked"},
		{"fe80::1", true, true, true, "link-local v6 always blocked"},
		{"224.0.0.1", true, false, true, "multicast v4"},
		{"ff02::1", true, false, true, "multicast v6"},

		// Private — denied by default, permitted with AllowPrivate
		{"10.0.0.1", false, false, true, "rfc1918 10/8 denied without opt-in"},
		{"10.0.0.1", true, false, false, "rfc1918 10/8 allowed with opt-in"},
		{"192.168.1.1", false, false, true, "rfc1918 192.168 denied"},
		{"172.16.0.1", false, false, true, "rfc1918 172.16 denied"},
		{"100.64.0.1", false, false, true, "CGNAT denied"},
		{"100.64.0.1", true, false, false, "CGNAT allowed with opt-in"},
		{"fc00::1", false, false, true, "ULA v6 denied"},
		{"fc00::1", true, false, false, "ULA v6 allowed with opt-in"},

		// Public — always allowed
		{"8.8.8.8", false, false, false, "public ipv4"},
		{"2606:4700:4700::1111", false, false, false, "public ipv6"},
	}
	for _, tc := range tests {
		t.Run(tc.ip+"/"+tc.why, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("bad test setup: %q is not an IP", tc.ip)
			}
			err := checkIP(ip, tc.allowPrivate, tc.allowLoopback)
			if tc.wantBlocked && err == nil {
				t.Fatalf("checkIP(%s, priv=%v, loop=%v) returned nil, expected ErrBlockedAddress", tc.ip, tc.allowPrivate, tc.allowLoopback)
			}
			if !tc.wantBlocked && err != nil {
				t.Fatalf("checkIP(%s, priv=%v, loop=%v) = %v, expected nil", tc.ip, tc.allowPrivate, tc.allowLoopback, err)
			}
			if err != nil && !errors.Is(err, ErrBlockedAddress) {
				t.Fatalf("error %v does not wrap ErrBlockedAddress", err)
			}
		})
	}
}

func TestClientRefusesIMDSLiteral(t *testing.T) {
	c := NewClient(Options{AllowPrivate: true})
	// Hitting the literal IMDS IP must fail at dial time, before any
	// network traffic, even when private addresses are otherwise allowed.
	_, err := c.Get("http://169.254.169.254/latest/meta-data/")
	if err == nil {
		t.Fatal("expected ErrBlockedAddress, got nil")
	}
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("expected ErrBlockedAddress, got: %v", err)
	}
}

func TestClientRefusesLoopbackLiteral(t *testing.T) {
	c := NewClient(Options{AllowPrivate: true})
	_, err := c.Get("http://127.0.0.1:1/")
	if err == nil {
		t.Fatal("expected ErrBlockedAddress, got nil")
	}
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("expected ErrBlockedAddress, got: %v", err)
	}
}

func TestClientAllowsLoopbackWhenOptedIn(t *testing.T) {
	c := NewClient(Options{AllowLoopback: true})
	// We don't care about the response; we only care that the dial check
	// doesn't reject the address. A connection-refused (no listener on
	// port 1) is acceptable evidence that we got past the SSRF guard.
	_, err := c.Get("http://127.0.0.1:1/")
	if err == nil {
		// Some environments may have a service on :1; that's fine, no
		// ErrBlockedAddress means the guard didn't trip.
		return
	}
	if errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("AllowLoopback=true should permit 127.0.0.1, got: %v", err)
	}
}

func TestClientRefusesPrivateLiteralByDefault(t *testing.T) {
	c := NewClient(Options{}) // AllowPrivate=false
	_, err := c.Get("http://10.0.0.1/")
	if err == nil {
		t.Fatal("expected ErrBlockedAddress, got nil")
	}
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("expected ErrBlockedAddress, got: %v", err)
	}
}
