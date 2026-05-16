// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package cache

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"os"
	"sync"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/logging"
	"github.com/envoyproxy/gateway/internal/xds/server/clusteridentity"
)

func newTestSnapshotCache(t *testing.T) *snapshotCache {
	t.Helper()
	logger := logging.DefaultLogger(os.Stderr, egv1a1.LogLevelInfo)
	cache := NewSnapshotCache(false, logger, nil)
	return cache.(*snapshotCache)
}

// TestOnStreamResponseConcurrentAccess verifies that OnStreamResponse and
// OnStreamOpen can safely run concurrently without a data race on streamIDNodeInfo.
func TestOnStreamResponseConcurrentAccess(t *testing.T) {
	sc := newTestSnapshotCache(t)

	err := sc.OnStreamOpen(context.Background(), 1, "")
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		streamID := int64(i + 100)

		go func() {
			defer wg.Done()
			sc.OnStreamResponse(context.Background(), 1, nil, nil)
		}()

		go func(id int64) {
			defer wg.Done()
			_ = sc.OnStreamOpen(context.Background(), id, "")
		}(streamID)
	}
	wg.Wait()
}

// TestOnStreamDeltaResponseConcurrentAccess verifies the same for delta streams.
func TestOnStreamDeltaResponseConcurrentAccess(t *testing.T) {
	sc := newTestSnapshotCache(t)

	err := sc.OnDeltaStreamOpen(context.Background(), 1, "")
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		streamID := int64(i + 100)

		go func() {
			defer wg.Done()
			sc.OnStreamDeltaResponse(1, nil, nil)
		}()

		go func(id int64) {
			defer wg.Done()
			_ = sc.OnDeltaStreamOpen(context.Background(), id, "")
		}(streamID)
	}
	wg.Wait()
}

// contextWithPeerCerts builds a context carrying a fake gRPC peer that
// presents the given certificates as its mTLS chain. Used to exercise the
// snapshot cache's cluster-identity binding without standing up an actual
// gRPC server.
func contextWithPeerCerts(certs []*x509.Certificate) context.Context {
	state := tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  certs,
	}
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: state},
	})
}

func certWithClusterSANs(t *testing.T, irKeys ...string) *x509.Certificate {
	t.Helper()
	c := &x509.Certificate{}
	for _, k := range irKeys {
		u, err := url.Parse("spiffe://envoy-gateway/cluster/" + k)
		if err != nil {
			t.Fatalf("bad URL in test setup: %v", err)
		}
		c.URIs = append(c.URIs, u)
	}
	return c
}

// TestOnStreamRequest_IdentityBindingRequireRejectsForeignCluster verifies
// that, with Require mode set, the snapshot cache refuses to serve a
// node.Cluster the connecting client's cert is not authorised for.
func TestOnStreamRequest_IdentityBindingRequireRejectsForeignCluster(t *testing.T) {
	logger := logging.DefaultLogger(os.Stderr, egv1a1.LogLevelInfo)
	sc := NewSnapshotCache(false, logger, clusteridentity.New(clusteridentity.ModeRequire)).(*snapshotCache)

	// Client presents a cert authorised only for tenant-a, but requests
	// tenant-b's snapshot.
	cert := certWithClusterSANs(t, "tenant-a")
	require.NoError(t, sc.OnStreamOpen(contextWithPeerCerts([]*x509.Certificate{cert}), 1, ""))

	req := &discoveryv3.DiscoveryRequest{
		Node: &corev3.Node{Id: "envoy-pod", Cluster: "tenant-b"},
	}
	err := sc.OnStreamRequest(1, req)
	require.Error(t, err)
	require.True(t, errors.Is(err, clusteridentity.ErrClusterIdentityMismatch),
		"expected ErrClusterIdentityMismatch, got: %v", err)
}

// TestOnStreamRequest_IdentityBindingRequireAcceptsAuthorisedCluster
// confirms the happy path: cert SAN matches node.Cluster, no rejection.
func TestOnStreamRequest_IdentityBindingRequireAcceptsAuthorisedCluster(t *testing.T) {
	logger := logging.DefaultLogger(os.Stderr, egv1a1.LogLevelInfo)
	sc := NewSnapshotCache(false, logger, clusteridentity.New(clusteridentity.ModeRequire)).(*snapshotCache)

	cert := certWithClusterSANs(t, "tenant-a")
	require.NoError(t, sc.OnStreamOpen(contextWithPeerCerts([]*x509.Certificate{cert}), 1, ""))

	req := &discoveryv3.DiscoveryRequest{
		Node: &corev3.Node{Id: "envoy-pod", Cluster: "tenant-a"},
	}
	require.NoError(t, sc.OnStreamRequest(1, req))
}

// TestOnStreamRequest_IdentityBindingAllowModePermitsForeignCluster
// asserts the legacy single-tenant behaviour is preserved when the
// validator is in Allow mode (or nil).
func TestOnStreamRequest_IdentityBindingAllowModePermitsForeignCluster(t *testing.T) {
	logger := logging.DefaultLogger(os.Stderr, egv1a1.LogLevelInfo)
	sc := NewSnapshotCache(false, logger, clusteridentity.New(clusteridentity.ModeAllow)).(*snapshotCache)

	cert := certWithClusterSANs(t, "tenant-a")
	require.NoError(t, sc.OnStreamOpen(contextWithPeerCerts([]*x509.Certificate{cert}), 1, ""))

	req := &discoveryv3.DiscoveryRequest{
		Node: &corev3.Node{Id: "envoy-pod", Cluster: "tenant-b"},
	}
	require.NoError(t, sc.OnStreamRequest(1, req))
}

// TestOnStreamDeltaRequest_IdentityBindingRequireRejects mirrors the
// SOTW test above for the delta-xDS code path.
func TestOnStreamDeltaRequest_IdentityBindingRequireRejects(t *testing.T) {
	logger := logging.DefaultLogger(os.Stderr, egv1a1.LogLevelInfo)
	sc := NewSnapshotCache(false, logger, clusteridentity.New(clusteridentity.ModeRequire)).(*snapshotCache)

	cert := certWithClusterSANs(t, "tenant-a")
	require.NoError(t, sc.OnDeltaStreamOpen(contextWithPeerCerts([]*x509.Certificate{cert}), 7, ""))

	req := &discoveryv3.DeltaDiscoveryRequest{
		Node: &corev3.Node{Id: "envoy-pod", Cluster: "tenant-b"},
	}
	err := sc.OnStreamDeltaRequest(7, req)
	require.Error(t, err)
	require.True(t, errors.Is(err, clusteridentity.ErrClusterIdentityMismatch))
}
