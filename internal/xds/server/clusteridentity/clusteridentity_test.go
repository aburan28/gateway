// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package clusteridentity

import (
	"crypto/x509"
	"errors"
	"net/url"
	"testing"
)

func certWithSANs(t *testing.T, dns []string, uris []string) *x509.Certificate {
	t.Helper()
	c := &x509.Certificate{DNSNames: dns}
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("bad URI in test setup: %v", err)
		}
		c.URIs = append(c.URIs, u)
	}
	return c
}

func TestAllowedClustersForCert(t *testing.T) {
	cert := certWithSANs(t,
		[]string{
			"cluster.tenant-a.envoy-gateway",
			"cluster.tenant-b.envoy-gateway",
			"some-other-name.example.com", // ignored
		},
		[]string{
			"spiffe://envoy-gateway/cluster/tenant-a", // dup with DNS
			"spiffe://envoy-gateway/cluster/tenant-c",
			"https://example.com", // ignored: wrong scheme
			"spiffe://example.com/role/admin", // ignored: not /cluster/
		})

	got := allowedClustersForCert(cert)
	wantSet := map[string]bool{"tenant-a": true, "tenant-b": true, "tenant-c": true}
	if len(got) != len(wantSet) {
		t.Fatalf("expected %d clusters, got %d: %v", len(wantSet), len(got), got)
	}
	for _, c := range got {
		if !wantSet[c] {
			t.Fatalf("unexpected cluster %q in %v", c, got)
		}
	}
}

func TestValidate_AllowMode(t *testing.T) {
	v := New(ModeAllow)
	if err := v.Validate(nil, "any-cluster"); err != nil {
		t.Fatalf("Allow mode must accept nil peer certs: %v", err)
	}
	cert := certWithSANs(t, []string{"cluster.tenant-a.envoy-gateway"}, nil)
	if err := v.Validate([]*x509.Certificate{cert}, "different-cluster"); err != nil {
		t.Fatalf("Allow mode must accept cross-cluster requests: %v", err)
	}
}

func TestValidate_RequireMode_Match(t *testing.T) {
	v := New(ModeRequire)
	cert := certWithSANs(t,
		nil,
		[]string{"spiffe://envoy-gateway/cluster/tenant-a"})
	if err := v.Validate([]*x509.Certificate{cert}, "tenant-a"); err != nil {
		t.Fatalf("expected match, got: %v", err)
	}
}

func TestValidate_RequireMode_DNSForm(t *testing.T) {
	v := New(ModeRequire)
	cert := certWithSANs(t,
		[]string{"cluster.tenant-a.envoy-gateway"},
		nil)
	if err := v.Validate([]*x509.Certificate{cert}, "tenant-a"); err != nil {
		t.Fatalf("expected DNS-SAN match, got: %v", err)
	}
}

func TestValidate_RequireMode_Mismatch(t *testing.T) {
	v := New(ModeRequire)
	cert := certWithSANs(t,
		[]string{"cluster.tenant-a.envoy-gateway"},
		nil)
	err := v.Validate([]*x509.Certificate{cert}, "tenant-b")
	if err == nil {
		t.Fatal("expected mismatch error, got nil")
	}
	if !errors.Is(err, ErrClusterIdentityMismatch) {
		t.Fatalf("expected ErrClusterIdentityMismatch, got: %v", err)
	}
}

func TestValidate_RequireMode_NoSANsRejects(t *testing.T) {
	v := New(ModeRequire)
	cert := certWithSANs(t, []string{"some-name.example.com"}, nil)
	err := v.Validate([]*x509.Certificate{cert}, "tenant-a")
	if err == nil {
		t.Fatal("expected rejection when cert has no cluster SANs")
	}
	if !errors.Is(err, ErrClusterIdentityMismatch) {
		t.Fatalf("expected ErrClusterIdentityMismatch, got: %v", err)
	}
}

func TestValidate_RequireMode_NoPeerCertsRejects(t *testing.T) {
	v := New(ModeRequire)
	err := v.Validate(nil, "tenant-a")
	if err == nil {
		t.Fatal("expected rejection when no peer cert presented")
	}
	if !errors.Is(err, ErrClusterIdentityMismatch) {
		t.Fatalf("expected ErrClusterIdentityMismatch, got: %v", err)
	}
}

func TestValidate_RequireMode_EmptyClusterRejects(t *testing.T) {
	v := New(ModeRequire)
	cert := certWithSANs(t,
		[]string{"cluster.tenant-a.envoy-gateway"},
		nil)
	err := v.Validate([]*x509.Certificate{cert}, "")
	if err == nil {
		t.Fatal("expected rejection for empty node.Cluster")
	}
	if !errors.Is(err, ErrClusterIdentityMismatch) {
		t.Fatalf("expected ErrClusterIdentityMismatch, got: %v", err)
	}
}

func TestValidate_NilValidator(t *testing.T) {
	var v *Validator
	if err := v.Validate(nil, "x"); err != nil {
		t.Fatalf("nil Validator must accept: %v", err)
	}
}
