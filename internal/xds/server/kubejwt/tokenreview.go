// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package kubejwt

import (
	"context"
	"fmt"
	"slices"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// GetKubernetesClient creates a Kubernetes client using in-cluster configuration.
func GetKubernetesClient() (*kubernetes.Clientset, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create in-cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	return clientset, nil
}

func (i *JWTAuthInterceptor) validateKubeJWT(ctx context.Context, token, nodeID string) error {
	tokenReview := &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token:     token,
			Audiences: []string{i.audience},
		},
	}

	tokenReview, err := i.clientset.AuthenticationV1().TokenReviews().Create(ctx, tokenReview, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to call TokenReview API to verify service account JWT: %w", err)
	}

	if tokenReview.Status.Error != "" {
		return fmt.Errorf("token review found error: %s", tokenReview.Status.Error)
	}

	if !slices.Contains(tokenReview.Status.User.Groups, "system:serviceaccounts") {
		return fmt.Errorf("the token is not a service account")
	}

	if !tokenReview.Status.Authenticated {
		return fmt.Errorf("token is not authenticated")
	}

	// Verify the TokenReview confirmed our requested audience. The Kubernetes API server only
	// echoes audiences it actually accepted, so a missing audience here means the token was
	// minted for a different audience and we must reject it.
	if !slices.Contains(tokenReview.Status.Audiences, i.audience) {
		return fmt.Errorf("token audience mismatch: expected %q to be present in %v", i.audience, tokenReview.Status.Audiences)
	}

	// The node ID in the xDS request MUST match the pod name embedded in the service-account
	// token. This binds an Envoy proxy's identity to its pod name and prevents one compromised
	// proxy (or any holder of a service-account token) from fetching another proxy's xDS
	// snapshot — which contains TLS private keys, OIDC client secrets, etc.
	//
	// The pod-binding claim is only populated for projected service-account tokens that were
	// minted with a bound object reference (the standard for in-cluster pods on K8s >= 1.22).
	// Legacy long-lived tokens or tokens minted with `kubectl create token` without
	// --bound-object-ref do NOT have this claim. Refusing such tokens here is intentional:
	// without the binding the interceptor cannot verify the requester is the proxy it claims
	// to be, so any cluster service account passing the prior groups check would otherwise
	// authenticate as any node.
	if tokenReview.Status.User.Extra == nil {
		return fmt.Errorf("token has no Extra claims; pod-binding claim required (use a projected service-account token with audience %q)", i.audience)
	}
	podName := tokenReview.Status.User.Extra[serviceaccount.PodNameKey]
	if len(podName) == 0 || podName[0] == "" {
		return fmt.Errorf("pod name not found in token review response (claim %q missing)", serviceaccount.PodNameKey)
	}
	if podName[0] != nodeID {
		return fmt.Errorf("pod name mismatch: expected %s, got %s", nodeID, podName[0])
	}

	return nil
}
