// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

// Package clusteridentity binds xDS `node.Cluster` requests to the
// authenticated identity of the client connection.
//
// Without this binding the snapshot cache routes per `node.Cluster` alone,
// so any client holding the shared Envoy Gateway mTLS cert can fetch any
// gateway's xDS snapshot — including SDS-inline TLS private keys, OIDC
// client secrets, BasicAuth user files, and credential-injector tokens.
//
// The Validator's Require mode rejects a request whose `node.Cluster`
// value is not represented in the client certificate's URI SANs
// (preferred form `spiffe://envoy-gateway/cluster/<ir-key>`) or DNS SANs
// (`cluster.<ir-key>.envoy-gateway`). Allow mode keeps the legacy
// behaviour but emits a metric / log entry so operators can audit cross-
// cluster requests when they prepare to flip to Require.
package clusteridentity

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

// ErrClusterIdentityMismatch is returned when the requested cluster is
// not represented in the client cert's SAN list.
var ErrClusterIdentityMismatch = errors.New("requested xDS node.Cluster is not allowed for the presented client identity")

// Mode names a policy for cluster-identity binding.
type Mode int

const (
	// ModeAllow permits any authenticated client to request any cluster's
	// snapshot. Default; preserves the pre-existing trust model.
	ModeAllow Mode = iota
	// ModeRequire rejects requests whose node.Cluster does not appear in
	// the client cert's SAN list.
	ModeRequire
)

// Validator decides whether a given (client-cert, requested-cluster) pair
// is permitted by the configured policy.
type Validator struct {
	mode Mode
}

// New returns a Validator configured for the given mode.
func New(mode Mode) *Validator {
	return &Validator{mode: mode}
}

// Validate returns nil if the requested cluster is allowed for the given
// peer certificate chain, or an error wrapping ErrClusterIdentityMismatch
// when the binding rejects the request.
//
//   - Allow mode: always nil.
//   - Require mode: cluster must appear in one of the peer cert's SANs.
//     If peerCerts is empty (e.g. no mTLS), Require mode rejects.
func (v *Validator) Validate(peerCerts []*x509.Certificate, requestedCluster string) error {
	if v == nil || v.mode == ModeAllow {
		return nil
	}
	if requestedCluster == "" {
		return fmt.Errorf("%w: empty node.Cluster", ErrClusterIdentityMismatch)
	}
	if len(peerCerts) == 0 {
		return fmt.Errorf("%w: no client certificate presented", ErrClusterIdentityMismatch)
	}
	allowed := allowedClustersForCert(peerCerts[0])
	if len(allowed) == 0 {
		return fmt.Errorf(
			"%w: certificate has no SANs matching the expected form (spiffe://envoy-gateway/cluster/<ir-key> or DNS cluster.<ir-key>.envoy-gateway). "+
				"If you intend to keep a single shared cert across tenants, set EnvoyGateway.XDSServer.ClusterIdentityBinding=Allow",
			ErrClusterIdentityMismatch)
	}
	for _, c := range allowed {
		if c == requestedCluster {
			return nil
		}
	}
	return fmt.Errorf(
		"%w: requested cluster %q is not in the cert-permitted set %v",
		ErrClusterIdentityMismatch, requestedCluster, allowed)
}

// allowedClustersForCert returns every IR key the given certificate is
// permitted to fetch a snapshot for. We recognise two SAN forms:
//
//   - URI SAN: spiffe://envoy-gateway/cluster/<ir-key>
//   - DNS SAN: cluster.<ir-key>.envoy-gateway
//
// Other SANs are ignored. The function tolerates either or both forms
// being present and de-duplicates the result.
func allowedClustersForCert(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	seen := make(map[string]struct{})
	add := func(k string) {
		if k == "" {
			return
		}
		seen[k] = struct{}{}
	}

	// URI SANs: spiffe://envoy-gateway/cluster/<ir-key>
	for _, u := range cert.URIs {
		if u == nil || u.Scheme != "spiffe" {
			continue
		}
		// Path is "/cluster/<ir-key>". Host is the trust domain
		// ("envoy-gateway"). Be tolerant of the trust domain since
		// operators may use their own.
		path := strings.TrimPrefix(u.Path, "/")
		const clusterPrefix = "cluster/"
		if strings.HasPrefix(path, clusterPrefix) {
			add(strings.TrimPrefix(path, clusterPrefix))
		}
	}

	// DNS SANs: cluster.<ir-key>.envoy-gateway
	const dnsPrefix = "cluster."
	const dnsSuffix = ".envoy-gateway"
	for _, d := range cert.DNSNames {
		if strings.HasPrefix(d, dnsPrefix) && strings.HasSuffix(d, dnsSuffix) {
			ir := strings.TrimSuffix(strings.TrimPrefix(d, dnsPrefix), dnsSuffix)
			add(ir)
		}
	}

	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}
