// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package kubejwt

import (
	"context"
	"io"
	"strings"
	"testing"

	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/logging"
)

// reviewResponse describes the TokenReview the fake API server should return.
type reviewResponse struct {
	authenticated bool
	groups        []string
	audiences     []string
	extra         map[string]authenticationv1.ExtraValue
	statusError   string
	createErr     error
}

func newInterceptor(t *testing.T, audience string, resp reviewResponse) *JWTAuthInterceptor {
	t.Helper()
	clientset := fake.NewSimpleClientset()
	clientset.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if resp.createErr != nil {
			return true, nil, resp.createErr
		}
		tr := action.(k8stesting.CreateAction).GetObject().(*authenticationv1.TokenReview)
		tr.Status = authenticationv1.TokenReviewStatus{
			Authenticated: resp.authenticated,
			Audiences:     resp.audiences,
			Error:         resp.statusError,
			User: authenticationv1.UserInfo{
				Groups: resp.groups,
				Extra:  resp.extra,
			},
		}
		return true, tr, nil
	})
	return NewJWTAuthInterceptor(logging.DefaultLogger(io.Discard, egv1a1.LogLevelInfo), clientset, "https://kubernetes.default.svc", audience)
}

func TestValidateKubeJWT(t *testing.T) {
	const (
		audience = "envoy-gateway"
		nodeID   = "envoy-pod-1"
	)
	saGroup := "system:serviceaccounts"

	cases := []struct {
		name    string
		nodeID  string
		resp    reviewResponse
		wantErr string
	}{
		{
			name:   "happy path: projected token, audience matches, pod name matches",
			nodeID: nodeID,
			resp: reviewResponse{
				authenticated: true,
				groups:        []string{saGroup},
				audiences:     []string{audience},
				extra: map[string]authenticationv1.ExtraValue{
					serviceaccount.PodNameKey: {nodeID},
				},
			},
		},
		{
			name:   "regression: nil Extra map must be rejected (was: silently authenticates as any node)",
			nodeID: nodeID,
			resp: reviewResponse{
				authenticated: true,
				groups:        []string{saGroup},
				audiences:     []string{audience},
				extra:         nil,
			},
			wantErr: "pod-binding claim required",
		},
		{
			name:   "regression: empty pod-name slice must be rejected (was: panic on podName[0])",
			nodeID: nodeID,
			resp: reviewResponse{
				authenticated: true,
				groups:        []string{saGroup},
				audiences:     []string{audience},
				extra: map[string]authenticationv1.ExtraValue{
					serviceaccount.PodNameKey: {},
				},
			},
			wantErr: "pod name not found",
		},
		{
			name:   "audience mismatch is rejected",
			nodeID: nodeID,
			resp: reviewResponse{
				authenticated: true,
				groups:        []string{saGroup},
				audiences:     []string{"different-audience"},
				extra: map[string]authenticationv1.ExtraValue{
					serviceaccount.PodNameKey: {nodeID},
				},
			},
			wantErr: "audience mismatch",
		},
		{
			name:   "node ID mismatch is rejected",
			nodeID: "envoy-pod-2",
			resp: reviewResponse{
				authenticated: true,
				groups:        []string{saGroup},
				audiences:     []string{audience},
				extra: map[string]authenticationv1.ExtraValue{
					serviceaccount.PodNameKey: {nodeID},
				},
			},
			wantErr: "pod name mismatch",
		},
		{
			name:   "non-service-account token is rejected",
			nodeID: nodeID,
			resp: reviewResponse{
				authenticated: true,
				groups:        []string{"system:authenticated"},
				audiences:     []string{audience},
				extra: map[string]authenticationv1.ExtraValue{
					serviceaccount.PodNameKey: {nodeID},
				},
			},
			wantErr: "not a service account",
		},
		{
			name:   "unauthenticated token is rejected",
			nodeID: nodeID,
			resp: reviewResponse{
				authenticated: false,
				groups:        []string{saGroup},
				audiences:     []string{audience},
				extra: map[string]authenticationv1.ExtraValue{
					serviceaccount.PodNameKey: {nodeID},
				},
			},
			wantErr: "not authenticated",
		},
		{
			name:   "TokenReview status error is surfaced",
			nodeID: nodeID,
			resp: reviewResponse{
				statusError: "invalid bearer token",
			},
			wantErr: "token review found error",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			i := newInterceptor(t, audience, tc.resp)
			err := i.validateKubeJWT(context.Background(), "fake-token", tc.nodeID)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}
