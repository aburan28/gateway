// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package gatewayapi

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/gatewayapi/resource"
	"github.com/envoyproxy/gateway/internal/ir"
)

const (
	patchPolicyTestController = "gateway.envoyproxy.io/gatewayclass-controller"
	patchPolicyTestGateway    = "gw"
	patchPolicyTestNamespace  = "tenant-a"
)

func newPatchPolicy(name, namespace string, patches []egv1a1.EnvoyJSONPatchConfig) *egv1a1.EnvoyPatchPolicy {
	return &egv1a1.EnvoyPatchPolicy{
		TypeMeta: metav1.TypeMeta{Kind: resource.KindEnvoyPatchPolicy, APIVersion: egv1a1.GroupVersion.String()},
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  namespace,
			Generation: 1,
		},
		Spec: egv1a1.EnvoyPatchPolicySpec{
			Type: egv1a1.JSONPatchEnvoyPatchType,
			TargetRef: gwapiv1.LocalPolicyTargetReference{
				Group: gwapiv1.GroupName,
				Kind:  resource.KindGateway,
				Name:  patchPolicyTestGateway,
			},
			JSONPatches: patches,
		},
	}
}

// patch builds a single benign JSONPatch operation targeting a Listener.
func benignPatch() egv1a1.EnvoyJSONPatchConfig {
	return egv1a1.EnvoyJSONPatchConfig{
		Type: egv1a1.ListenerEnvoyResourceType,
		Name: "default/gw/listener-0",
		Operation: egv1a1.JSONPatchOperation{
			Op:   egv1a1.JSONPatchOperationType("add"),
			Path: ptr.To("/some_safe_field"),
			Value: &apiextensionsv1.JSON{
				Raw: []byte(`"ok"`),
			},
		},
	}
}

// dangerousPatch builds a JSONPatch operation whose value carries a
// transport_socket field, mirroring the canonical TLS-downgrade exploit.
func dangerousPatchTransportSocket() egv1a1.EnvoyJSONPatchConfig {
	return egv1a1.EnvoyJSONPatchConfig{
		Type: egv1a1.ClusterEnvoyResourceType,
		Name: "default/gw/upstream",
		Operation: egv1a1.JSONPatchOperation{
			Op:   egv1a1.JSONPatchOperationType("replace"),
			Path: ptr.To("/transport_socket"),
			Value: &apiextensionsv1.JSON{
				Raw: []byte(`{"name":"envoy.transport_sockets.raw_buffer"}`),
			},
		},
	}
}

// dangerousPatchLuaInjection adds an envoy.filters.http.lua filter that
// would otherwise execute attacker-supplied code in the data plane.
func dangerousPatchLuaInjection() egv1a1.EnvoyJSONPatchConfig {
	return egv1a1.EnvoyJSONPatchConfig{
		Type: egv1a1.ListenerEnvoyResourceType,
		Name: "default/gw/listener-0",
		Operation: egv1a1.JSONPatchOperation{
			Op:   egv1a1.JSONPatchOperationType("add"),
			Path: ptr.To("/filter_chains/0/filters/0/typed_config/http_filters/-"),
			Value: &apiextensionsv1.JSON{
				Raw: []byte(`{"name":"envoy.filters.http.lua","typed_config":{"inline_code":"function envoy_on_request() end"}}`),
			},
		},
	}
}

// dangerousSecretPatch targets the SDS Secret resource type directly.
func dangerousSecretPatch() egv1a1.EnvoyJSONPatchConfig {
	return egv1a1.EnvoyJSONPatchConfig{
		Type: egv1a1.SecretEnvoyResourceType,
		Name: "default/gw/sds-secret",
		Operation: egv1a1.JSONPatchOperation{
			Op:    egv1a1.JSONPatchOperationType("replace"),
			Path:  ptr.To("/tls_certificate/private_key/inline_string"),
			Value: &apiextensionsv1.JSON{Raw: []byte(`"attacker-key"`)},
		},
	}
}

func translatorWithPatchPolicy(allowedNS []string, allowDangerous bool) (*Translator, resource.XdsIRMap) {
	t := &Translator{
		GatewayControllerName:        patchPolicyTestController,
		EnvoyPatchPolicyEnabled:      true,
		AllowedPatchPolicyNamespaces: allowedNS,
		AllowDangerousPatches:        allowDangerous,
	}
	gatewayNN := types.NamespacedName{Namespace: patchPolicyTestNamespace, Name: patchPolicyTestGateway}
	xdsIR := resource.XdsIRMap{}
	xdsIR[t.IRKey(gatewayNN)] = &ir.Xds{}
	return t, xdsIR
}

func resolveErrorMessage(p *egv1a1.EnvoyPatchPolicy) string {
	for _, parent := range p.Status.Ancestors {
		for _, cond := range parent.Conditions {
			if cond.Type == string(gwapiv1.PolicyConditionAccepted) && cond.Status == metav1.ConditionFalse {
				return cond.Message
			}
		}
	}
	return ""
}

func TestProcessEnvoyPatchPolicies_NamespaceAllowlist(t *testing.T) {
	t.Run("nil allowlist permits any namespace (backwards-compatible)", func(t *testing.T) {
		tr, xdsIR := translatorWithPatchPolicy(nil, false)
		p := newPatchPolicy("p", patchPolicyTestNamespace, []egv1a1.EnvoyJSONPatchConfig{benignPatch()})
		tr.ProcessEnvoyPatchPolicies([]*egv1a1.EnvoyPatchPolicy{p}, xdsIR)
		require.Empty(t, resolveErrorMessage(p), "expected policy to be Accepted")
	})

	t.Run("empty allowlist denies every namespace", func(t *testing.T) {
		tr, xdsIR := translatorWithPatchPolicy([]string{}, false)
		p := newPatchPolicy("p", patchPolicyTestNamespace, []egv1a1.EnvoyJSONPatchConfig{benignPatch()})
		tr.ProcessEnvoyPatchPolicies([]*egv1a1.EnvoyPatchPolicy{p}, xdsIR)
		msg := resolveErrorMessage(p)
		require.NotEmpty(t, msg)
		require.True(t, strings.Contains(msg, "AllowedPatchPolicyNamespaces"))
	})

	t.Run("allowlist denies non-listed namespace", func(t *testing.T) {
		tr, xdsIR := translatorWithPatchPolicy([]string{"other-ns"}, false)
		p := newPatchPolicy("p", patchPolicyTestNamespace, []egv1a1.EnvoyJSONPatchConfig{benignPatch()})
		tr.ProcessEnvoyPatchPolicies([]*egv1a1.EnvoyPatchPolicy{p}, xdsIR)
		msg := resolveErrorMessage(p)
		require.NotEmpty(t, msg)
		require.True(t, strings.Contains(msg, patchPolicyTestNamespace))
	})

	t.Run("allowlist permits listed namespace", func(t *testing.T) {
		tr, xdsIR := translatorWithPatchPolicy([]string{patchPolicyTestNamespace}, false)
		p := newPatchPolicy("p", patchPolicyTestNamespace, []egv1a1.EnvoyJSONPatchConfig{benignPatch()})
		tr.ProcessEnvoyPatchPolicies([]*egv1a1.EnvoyPatchPolicy{p}, xdsIR)
		require.Empty(t, resolveErrorMessage(p))
	})
}

func TestProcessEnvoyPatchPolicies_DangerousFieldDenyList(t *testing.T) {
	cases := []struct {
		name        string
		patches     []egv1a1.EnvoyJSONPatchConfig
		wantInError string
	}{
		{
			name:        "transport_socket path rewrite is rejected",
			patches:     []egv1a1.EnvoyJSONPatchConfig{dangerousPatchTransportSocket()},
			wantInError: "transport_socket",
		},
		{
			name:        "lua filter injection in value is rejected",
			patches:     []egv1a1.EnvoyJSONPatchConfig{dangerousPatchLuaInjection()},
			wantInError: "envoy.filters.http.lua",
		},
		{
			name:        "patching the SDS Secret type is rejected",
			patches:     []egv1a1.EnvoyJSONPatchConfig{dangerousSecretPatch()},
			wantInError: "Secret",
		},
		{
			name: "mixed-policy with one dangerous patch is rejected wholesale",
			patches: []egv1a1.EnvoyJSONPatchConfig{
				benignPatch(),
				dangerousPatchTransportSocket(),
			},
			wantInError: "transport_socket",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr, xdsIR := translatorWithPatchPolicy(nil, false)
			p := newPatchPolicy("p", patchPolicyTestNamespace, tc.patches)
			tr.ProcessEnvoyPatchPolicies([]*egv1a1.EnvoyPatchPolicy{p}, xdsIR)
			msg := resolveErrorMessage(p)
			require.NotEmpty(t, msg, "expected policy to be rejected")
			require.True(t, strings.Contains(msg, tc.wantInError), "want %q in %q", tc.wantInError, msg)
			// Verify the IR did NOT pick up the rejected patch.
			gwXdsIR := xdsIR[tr.IRKey(types.NamespacedName{Namespace: patchPolicyTestNamespace, Name: patchPolicyTestGateway})]
			require.Empty(t, gwXdsIR.EnvoyPatchPolicies, "rejected policy should not appear in IR")
		})
	}

	t.Run("AllowDangerousPatches=true permits transport_socket rewrite", func(t *testing.T) {
		tr, xdsIR := translatorWithPatchPolicy(nil, true)
		p := newPatchPolicy("p", patchPolicyTestNamespace, []egv1a1.EnvoyJSONPatchConfig{dangerousPatchTransportSocket()})
		tr.ProcessEnvoyPatchPolicies([]*egv1a1.EnvoyPatchPolicy{p}, xdsIR)
		require.Empty(t, resolveErrorMessage(p), "expected policy to be Accepted when AllowDangerousPatches=true")
	})
}

func TestPatchOperationIsDangerous(t *testing.T) {
	tests := []struct {
		name string
		op   ir.JSONPatchOperation
		want bool
	}{
		{
			name: "benign path",
			op:   ir.JSONPatchOperation{Path: ptr.To("/some_field")},
			want: false,
		},
		{
			name: "path contains validation_context",
			op:   ir.JSONPatchOperation{Path: ptr.To("/common_tls_context/validation_context/trusted_ca")},
			want: true,
		},
		{
			name: "value carries transport_socket key",
			op: ir.JSONPatchOperation{
				Path:  ptr.To("/cluster"),
				Value: &apiextensionsv1.JSON{Raw: []byte(`{"transport_socket":{}}`)},
			},
			want: true,
		},
		{
			name: "value contains transport_socket as a substring of an unrelated string is NOT flagged",
			op: ir.JSONPatchOperation{
				Path:  ptr.To("/cluster/description"),
				Value: &apiextensionsv1.JSON{Raw: []byte(`"this is documentation about transport_socket fields"`)},
			},
			want: false, // substring without `"key":` form
		},
		{
			name: "ext_authz value rejected",
			op: ir.JSONPatchOperation{
				Path:  ptr.To("/listener/filter_chains/0"),
				Value: &apiextensionsv1.JSON{Raw: []byte(`{"name":"envoy.filters.http.ext_authz"}`)},
			},
			want: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := patchOperationIsDangerous(&tc.op) != ""
			require.Equal(t, tc.want, got)
		})
	}
}
