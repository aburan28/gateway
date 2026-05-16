// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package gatewayapi

import (
	"fmt"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/types"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/gatewayapi/resource"
	"github.com/envoyproxy/gateway/internal/gatewayapi/status"
	"github.com/envoyproxy/gateway/internal/ir"
)

// dangerousPatchFieldFragments are field names that, when present in an
// EnvoyPatchPolicy operation path or value, cause the patch to be rejected
// unless AllowDangerousPatches is set. The list is intentionally
// over-inclusive: false positives surface as actionable status errors,
// while a missed dangerous patch is silent xDS compromise.
var dangerousPatchFieldFragments = []string{
	"tls_certificate",                    // SDS / inline TLS certs and keys
	"tls_certificate_sds_secret_configs", // SDS lookup
	"common_tls_context",                 // wrapper around TLS bits
	"validation_context",                 // CA pinning / peer verification
	"transport_socket",                   // includes downstream/upstream TLS
	"envoy.filters.http.lua",             // executes arbitrary controller-supplied code in Envoy
	"envoy.filters.http.wasm",            // executes arbitrary Wasm in Envoy
	"envoy.filters.http.ext_authz",       // attacker can route auth decisions
	"envoy.filters.http.ext_proc",        // attacker can mutate every request/response
}

// patchTargetsSecret reports whether the JSONPatch type-string names the
// Envoy Secret resource — SDS-distributed TLS keys live there and there
// is no legitimate EnvoyPatchPolicy use case. The Type field of an
// EnvoyJSONPatchConfig is the full xDS type URL.
const envoySecretTypeURL = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"

func patchTargetsSecret(patchType string) bool {
	return strings.EqualFold(patchType, envoySecretTypeURL)
}

// patchOperationIsDangerous returns a non-empty reason string when the
// operation targets a field this fix gates behind AllowDangerousPatches.
// It inspects the Path / JSONPath strings AND the JSON-encoded Value
// because a JSONPatch `add` of `{"transport_socket": {...}}` at a generic
// parent path bypasses any path-only check.
func patchOperationIsDangerous(op *ir.JSONPatchOperation) string {
	if op == nil {
		return ""
	}
	for _, src := range []struct {
		label, val string
	}{
		{"path", strings.ToLower(deref(op.Path))},
		{"jsonPath", strings.ToLower(deref(op.JSONPath))},
	} {
		if src.val == "" {
			continue
		}
		for _, frag := range dangerousPatchFieldFragments {
			if strings.Contains(src.val, frag) {
				return fmt.Sprintf("operation %s %q references protected field %q", src.label, src.val, frag)
			}
		}
	}
	if op.Value != nil && op.Value.Raw != nil {
		body := strings.ToLower(string(op.Value.Raw))
		for _, frag := range dangerousPatchFieldFragments {
			// Match against the quoted form. For protocol field names like
			// `transport_socket` this matches the `"transport_socket":`
			// key. For filter identifiers like `envoy.filters.http.lua`
			// this matches the `"envoy.filters.http.lua"` value of a
			// filter's `name` field. Both forms imply the patch is
			// rewriting a security-sensitive xDS field.
			if strings.Contains(body, fmt.Sprintf("%q", frag)) {
				return fmt.Sprintf("operation value carries protected field %q", frag)
			}
		}
	}
	return ""
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// namespaceAllowed returns true when the given policy namespace is
// permitted given the allowlist. A nil allowlist means "all namespaces".
func namespaceAllowed(policyNamespace string, allowlist []string) bool {
	if allowlist == nil {
		return true
	}
	return slices.Contains(allowlist, policyNamespace)
}

func (t *Translator) ProcessEnvoyPatchPolicies(envoyPatchPolicies []*egv1a1.EnvoyPatchPolicy, xdsIR resource.XdsIRMap) {
	// EnvoyPatchPolicies are already sorted by the provider layer (priority, then timestamp, then name)

	for _, policy := range envoyPatchPolicies {
		var (
			ancestorRef gwapiv1.ParentReference
			resolveErr  *status.PolicyResolveError
			targetKind  string
			irKey       string
		)

		refKind, refName := policy.Spec.TargetRef.Kind, policy.Spec.TargetRef.Name
		if t.MergeGateways {
			targetKind = resource.KindGatewayClass
			// if ref GatewayClass name is not same as t.GatewayClassName, it will be skipped in L53.
			irKey = string(refName)
			ancestorRef = gwapiv1.ParentReference{
				Group: GroupPtr(gwapiv1.GroupName),
				Kind:  KindPtr(targetKind),
				Name:  refName,
			}

		} else {
			targetKind = resource.KindGateway
			gatewayNN := types.NamespacedName{
				Namespace: policy.Namespace,
				Name:      string(refName),
			}
			irKey = t.IRKey(gatewayNN)
			ancestorRef = getAncestorRefForPolicy(gatewayNN, nil)
		}

		gwXdsIR, ok := xdsIR[irKey]
		if !ok {
			// The TargetRef Gateway is not an accepted Gateway, then skip processing.
			continue
		}

		// Create the IR with the context need to publish the status later
		policyIR := ir.EnvoyPatchPolicy{}
		policyIR.Name = policy.Name
		policyIR.Namespace = policy.Namespace
		policyIR.Generation = policy.Generation
		policyIR.Status = &policy.Status

		// Append the IR
		gwXdsIR.EnvoyPatchPolicies = append(gwXdsIR.EnvoyPatchPolicies, &policyIR)

		// Ensure EnvoyPatchPolicy is enabled
		if !t.EnvoyPatchPolicyEnabled {
			resolveErr = &status.PolicyResolveError{
				Reason:  egv1a1.PolicyReasonDisabled,
				Message: "EnvoyPatchPolicy is disabled in the EnvoyGateway configuration",
			}
			status.SetResolveErrorForPolicyAncestor(&policy.Status,
				&ancestorRef,
				t.GatewayControllerName,
				policy.Generation,
				resolveErr,
			)

			continue
		}

		// Enforce the per-deployment EnvoyPatchPolicy namespace allowlist
		// before any patch contents are consulted. Operators set the
		// allowlist on the EnvoyGateway config to limit which namespaces
		// can author a feature whose blast radius is documented as
		// "complete security compromise".
		if !namespaceAllowed(policy.Namespace, t.AllowedPatchPolicyNamespaces) {
			resolveErr = &status.PolicyResolveError{
				Reason:  gwapiv1.PolicyReasonInvalid,
				Message: fmt.Sprintf("EnvoyPatchPolicy in namespace %q is not in the configured AllowedPatchPolicyNamespaces", policy.Namespace),
			}
			status.SetResolveErrorForPolicyAncestor(&policy.Status,
				&ancestorRef,
				t.GatewayControllerName,
				policy.Generation,
				resolveErr,
			)
			continue
		}

		// Ensure EnvoyPatchPolicy is targeting to a support type
		if policy.Spec.TargetRef.Group != gwapiv1.GroupName || string(refKind) != targetKind {
			message := fmt.Sprintf("TargetRef.Group:%s TargetRef.Kind:%s, only TargetRef.Group:%s and TargetRef.Kind:%s is supported.",
				policy.Spec.TargetRef.Group, policy.Spec.TargetRef.Kind, gwapiv1.GroupName, targetKind)

			resolveErr = &status.PolicyResolveError{
				Reason:  gwapiv1.PolicyReasonInvalid,
				Message: message,
			}
			status.SetResolveErrorForPolicyAncestor(&policy.Status,
				&ancestorRef,
				t.GatewayControllerName,
				policy.Generation,
				resolveErr,
			)

			continue
		}

		// Save the patch — but first run the per-operation deny-list when
		// AllowDangerousPatches is not set. The legacy behavior (no field
		// guardrails) is recoverable by flipping the EnvoyGateway flag.
		// Patches targeting the SDS Secret xDS type are rejected
		// regardless of their inner path/value, because there is no
		// legitimate downstream EnvoyPatchPolicy use case for rewriting
		// distributed TLS material.
		var dangerousReason string
		for _, patch := range policy.Spec.JSONPatches {
			irPatch := ir.JSONPatchConfig{}
			irPatch.Type = string(patch.Type)
			irPatch.Name = patch.Name
			irPatch.Operation.Op = ir.JSONPatchOp(patch.Operation.Op)
			irPatch.Operation.Path = patch.Operation.Path
			irPatch.Operation.JSONPath = patch.Operation.JSONPath
			irPatch.Operation.From = patch.Operation.From
			irPatch.Operation.Value = patch.Operation.Value

			if !t.AllowDangerousPatches && dangerousReason == "" {
				switch {
				case patchTargetsSecret(irPatch.Type):
					dangerousReason = fmt.Sprintf("patch type %q targets SDS Secret resources", irPatch.Type)
				default:
					if r := patchOperationIsDangerous(&irPatch.Operation); r != "" {
						dangerousReason = r
					}
				}
			}

			policyIR.JSONPatches = append(policyIR.JSONPatches, &irPatch)
		}

		if dangerousReason != "" {
			// Drop the policy from the IR so the dangerous patch never
			// reaches the xDS translator, even if other patches in the
			// same policy were benign — partial application of an
			// operator's intent is a worse failure mode than full
			// rejection with a clear status condition.
			gwXdsIR.EnvoyPatchPolicies = gwXdsIR.EnvoyPatchPolicies[:len(gwXdsIR.EnvoyPatchPolicies)-1]
			resolveErr = &status.PolicyResolveError{
				Reason:  gwapiv1.PolicyReasonInvalid,
				Message: fmt.Sprintf("EnvoyPatchPolicy contains a dangerous patch: %s. Set ExtensionAPIs.AllowDangerousPatches=true in the EnvoyGateway config to permit it.", dangerousReason),
			}
			status.SetResolveErrorForPolicyAncestor(&policy.Status,
				&ancestorRef,
				t.GatewayControllerName,
				policy.Generation,
				resolveErr,
			)
			continue
		}

		// Set Accepted=True
		status.SetAcceptedForPolicyAncestor(&policy.Status, &ancestorRef, t.GatewayControllerName, policy.Generation)
	}
}
