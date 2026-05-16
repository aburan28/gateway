# Security Review: Validation, IR, and Dependencies

Scope: input validation across the Gateway API translator, IR consistency, CRD validation gaps, dependency security, Lua sandbox, EnvoyPatchPolicy trust model, and miscellaneous Go gotchas.

---

## [HIGH] EnvoyPatchPolicy gating is global, not RBAC-scoped — any namespaced creator can inject arbitrary Envoy xDS
**File:** internal/gatewayapi/envoypatchpolicy.go:20-119; api/v1alpha1/envoypatchpolicy_types.go:30-138; api/v1alpha1/envoygateway_types.go:298-306
**Description:**
EnvoyPatchPolicy is a namespaced CRD whose `JSONPatches[*].Operation.Value` accepts an arbitrary `apiextensionsv1.JSON` blob that is splat-applied onto the generated Envoy xDS (listener/route/cluster/secret resource types are enumerated in a kubebuilder enum, but everything below the typed URL is unconstrained). Concretely, a user who can `create envoypatchpolicies` in any namespace where a Gateway lives can:
- Add an `lua` HTTP filter that exfiltrates request bodies (bypassing the luavalidator entirely — see separate finding).
- Replace TLS secret material on a listener.
- Add a `direct_response` that returns attacker-controlled credentials.
- Change cluster transport sockets to disable certificate verification (downgrade an `https://` upstream).
- Inject an `ext_authz` filter pointed at the attacker's gRPC server, capturing all requests.

The only gating today is the cluster-wide feature flag `EnvoyGateway.ExtensionAPIs.EnableEnvoyPatchPolicy`. Once that flag is on, the policy author needs only `create envoypatchpolicies.gateway.envoyproxy.io` in any namespace whose Gateway they can target (`policy.Namespace == gatewayNN.Namespace` per line 44-49). There is no admission-time check that the patch does not, e.g., drop TLS, swap a cert, or rewrite SDS. There is no namespace boundary check between the policy and the patched resource (the policy can rewrite cluster endpoints whose Backend lives in a different namespace, since at xDS-patch time the namespace is irrelevant).

The CRD's own godoc (envoygateway_types.go:303-305) does call this out: *"Enabling EnvoyPatchPolicy may lead to complete security compromise of your system. Users with EnvoyPatchPolicy permissions can inject arbitrary configuration to proxies..."* — i.e., the security model is "treat ability to create EnvoyPatchPolicy as cluster-admin equivalent." That is informally documented but **not enforced**, and the CRD scope is namespaced, so any RBAC role granting policy creation in a workload namespace effectively grants cluster-admin to that proxy.

**Recommendation:**
- Strongly consider making the CRD `ClusterScoped` so that RBAC is naturally cluster-wide, matching the trust model. (Breaking change, but matches reality.)
- At minimum, add an admission webhook or runtime check that flags/rejects patches that:
  - target `transport_sockets`, `tls_certificates`, `tls_certificate_sds_secret_configs`, `validation_context`, `common_tls_context`;
  - add `lua`/`wasm`/`ext_authz`/`ext_proc` filters not present in the base config;
  - patch the `Secret` xDS type at all.
- Require an explicit allowlist of policy namespaces in `EnvoyGateway` (e.g., `AllowedPatchPolicyNamespaces []string`), defaulting to empty (none) when `EnableEnvoyPatchPolicy=true`.
- Surface a `Warning` admission response when any patch is created that mutates TLS-related fields.

---

## [HIGH] Lua sandbox can be bypassed via `getfenv` / `setfenv` (and other Lua 5.1 escape hatches)
**File:** internal/gatewayapi/luavalidator/security.lua:102-117; internal/gatewayapi/luavalidator/lua_validator.go:97-115
**Description:**
The sandbox nulls a long list of globals (`io.popen`, `os.execute`, `os.exit`, `require`, `loadfile`, `dofile`, `package`, `debug`, `load`, `loadstring`, `rawget/rawset`, `getmetatable/setmetatable`, and `_G`). However, gopher-lua emulates Lua 5.1 semantics and exposes `getfenv` / `setfenv`, which are **not** nilled. Any of the following recover the globals table after `security.lua` has nulled `_G`:

```lua
function envoy_on_request(request_handle)
  local g = getfenv(0)       -- environment of the calling chunk = globals
  -- g.io, g.os, g.coroutine, g.string, etc. are intact
  g.os.getenv = nil           -- bypass sanitized wrappers
  -- or call raw io.open via getfenv to escape path validation:
  local f = g.io.open("/etc/passwd", "r")   -- still wrapped but path check is the only line of defense
end
```

Even without `getfenv`, the security sandbox has gaps:
- `coroutine` is not nilled, and the test suite (lua_validator_test.go:735) confirms it works.
- `string.rep` is not bounded — `string.rep("A", 1<<28)` allocates ~256 MB inside the controller process. The gopher-lua `RegistryMaxSize: 5120` (lua_validator.go:101) governs the Lua *registry* (variable slots), not the Go-heap allocations done by string operations.
- `string.dump` is available, and combined with `load` (which is nilled, good) is harmless, but `string.format("%q", ...)` and `string.gmatch` on attacker patterns can still cost CPU. The 5-second deadline mitigates most CPU attacks but not memory exhaustion.
- The `_G = nil` trick relies on `_G` being the *only* alias to globals. In Lua 5.1 it is *not* — every chunk's `_ENV`-equivalent is its environment, reachable via `getfenv`.

Impact: an attacker who can submit an EnvoyExtensionPolicy with a Lua body (and the cluster admin has not disabled the feature) can read environment variables, secret-mount paths the controller can see, and otherwise sensitive controller-pod state — even though the explicit `os.getenv` wrapper would block direct calls.

The Lua execution sandbox is also documented as guarding against the GHSA-xrwg-mqj6-6m22 advisory (referenced in lua_validator.go:127), which suggests the design already accepted that Lua executes in-controller; the gaps above represent a regression of the same threat.

**Recommendation:**
- Add `getfenv = nil; setfenv = nil; coroutine = nil` to security.lua. Verify with a unit test that `assert(getfenv == nil)` after sandbox load.
- Bound string library: at minimum, wrap `string.rep` with a length cap. Better: drop `SkipOpenLibs: false` and selectively open only the libraries needed for the mock environment.
- Run the validator in a separate goroutine with a hard memory cap, or better, in a separate subprocess. The current `defer recover()` (lua_validator.go:135) catches Go panics but not OOMKills.
- Add explicit negative tests for `getfenv(0).io.open(...)`, `string.rep(...)`, `coroutine.wrap(...)` accessing globals — those tests should fail today.
- Consider gating execution behind the same `LuaValidation = "Disabled"` opt-out by default; today the default is `Strict` (lua_validator.go:90), which means *unconditional execution* of every user-submitted Lua chunk inside the controller — a denial-of-service surface that scales with the number of EnvoyExtensionPolicies.

---

## [HIGH] Nil-pointer dereference on `*listener.TLS.Mode` in TLSProtocolType handling
**File:** internal/gatewayapi/listener.go:66-78
**Description:**
```go
case gwapiv1.TLSProtocolType:
    if listener.TLS != nil {
        switch *listener.TLS.Mode {     // <-- panics if Mode == nil
```
`listener.TLS.Mode` is a `*gwapiv1.TLSModeType` and is documented as optional. Every other site in the codebase that touches it does `listener.TLS.Mode != nil && *listener.TLS.Mode == ...` (validate.go:548, 577, 589). This single site is unguarded.

In normal K8s flow the upstream Gateway-API CRD defaults Mode to `Terminate`, so the field is rarely nil. However:
- The file-provider / `egctl x translate` path (resource/load.go) goes through `defaulter.ApplyDefault`, but if the upstream OpenAPI schema does not set the default (it has historically been inconsistent across gateway-api releases), the field arrives nil.
- A custom admission stack or a controller-side write that bypasses defaulting (e.g., via dry-run server-side apply with `--force-conflicts` on a stripped object) can produce nil Mode.
- This path is reached *before* `validateTLSConfiguration` (listener.go:100), which is where the defensive nil-check lives — so the panic happens prior to any validation.

Impact: a single user-controlled gateway listener with `protocol: TLS` and no `mode` crashes the entire translator goroutine, taking the control plane offline.

**Recommendation:** mirror the validate.go pattern and only deref after a nil check:
```go
case gwapiv1.TLSProtocolType:
    if listener.TLS != nil && listener.TLS.Mode != nil {
        switch *listener.TLS.Mode { ... }
    } else {
        t.validateAllowedRoutes(listener, resource.KindTCPRoute, resource.KindTLSRoute)
    }
```

---

## [MEDIUM] Nil-pointer dereference on `*luaCode` when Inline is unset
**File:** internal/gatewayapi/envoyextensionpolicy.go:724-737
**Description:**
```go
var luaCode *string
if lua.Type == egv1a1.LuaValueTypeValueRef {
    luaCode, err = t.getLuaBodyFromLocalObjectReference(lua.ValueRef, policy.Namespace)
} else {
    luaCode = lua.Inline                       // <-- may be nil
}
if err != nil { return nil, err }

if err = luavalidator.NewLuaValidator(*luaCode, envoyProxy).Validate(); err != nil {
                                       // ^^^ panics if luaCode is nil
```

The CEL XValidation on the `Lua` type (lua_types.go:25) enforces that when `type == Inline` then `inline` is set, but this is only enforced by the API server *if CEL admission validation is enabled and the CRD installation was not rolled back to a pre-CEL version*. In any of these scenarios `lua.Inline` can be nil:
- File-provider / egctl-translate path where CEL is not run.
- Older clusters (`<1.25`) where CEL XValidation is silently ignored.
- A controller-supplied object that arrives via a transformer/extension server which bypasses admission.

A nil-deref here panics the gateway-api translator and prevents reconciliation.

**Recommendation:**
```go
if luaCode == nil || *luaCode == "" {
    return nil, fmt.Errorf("lua source is empty for policy %s", name)
}
```
Add this guard before the call to `NewLuaValidator`.

---

## [MEDIUM] Lua validator executes user code by default and is the *primary* DoS amplifier
**File:** internal/gatewayapi/luavalidator/lua_validator.go:56-91
**Description:**
`getLuaValidation` defaults to `Strict` (line 90), which dispatches to `runLua` and *actually executes* the user-provided Lua chunk inside the controller (line 81). The chunk is wrapped to call `envoy_on_request(StreamHandle)` or `envoy_on_response(StreamHandle)`, so any work the user puts in the function body is performed on the control plane.

Even with the 5-second deadline (line 23) and the recover-from-panic (line 135), this means:
- Every reconciliation of an EnvoyExtensionPolicy adds up to 5 s of CPU on the controller pod (or up to 10 s if both `envoy_on_request` and `envoy_on_response` are defined — see line 57-69, which calls `validate` twice).
- N policies in a namespace → up to 10·N seconds of serialized validator work per translator pass. Even if validator runs are concurrent, memory pressure from each `lua.NewState` plus mocks compounds.
- `recover()` in `runLua` only catches Go panics; OOM from large allocations (e.g., `local t = {} for i=1,1e8 do t[i]=string.rep("x",1024) end`) is **not** recoverable and will SIGKILL the controller.

**Recommendation:**
- Change the default `LuaValidation` to `SyntaxOnly` (loadLua path, line 159) and document `Strict` as an opt-in for environments where the operator has resource isolation in place.
- Cap the number of concurrent Lua VMs (semaphore at 2-4).
- For Strict mode, run the validator out-of-process (e.g., a dedicated subprocess with `prlimit`-style memory caps via `setrlimit`/cgroups) so that an OOM doesn't take down the controller.
- Halve the per-side timeout (5 s × 2 = 10 s of controller time per policy is already a lot for a control-plane operation).

---

## [MEDIUM] `addMissingServices` dereferences `*ref.Port` without nil-check
**File:** internal/gatewayapi/resource/load.go:614-631
**Description:**
```go
for _, ref := range refs {
    if ref.Kind == nil || *ref.Kind != KindService { continue }
    ...
    port := *ref.Port           // <-- panic if ref.Port == nil
```
`BackendRef.Port` is `*PortNumber` and **may be nil** per the gateway-api type definition (e.g., TLSRoute, TCPRoute used to allow nil ports, and a `Backend`-kind ref also nil). The earlier `if ref.Kind != KindService` filter is the only one and lets through any explicit `Kind: Service` ref with a nil Port. Validation of nil-port-on-Service refs lives separately (validate.go:168-183), but this code path is the *file provider* loader, which runs before any translator-side validation.

Impact: `egctl x translate` or any `LoadResourcesFromYAMLBytes` consumer crashes on a malformed but plausibly-valid HTTPRoute YAML where `port` is omitted from a `kind: Service` backendRef. Not a runtime/control-plane CVE, but breaks CLI tooling on attacker- or operator-supplied YAML.

**Recommendation:**
```go
if ref.Port == nil { continue }
port := *ref.Port
```

---

## [MEDIUM] `regex.Validate` only validates RE2 syntax — no length or complexity bound
**File:** internal/utils/regex/regex.go:14-20; internal/gatewayapi/route.go:668, 684, 701, 729, 1176, 1193, 1198
**Description:**
User-supplied regexes (route path/header/query/cookie matches, GRPC method match) are syntactically validated by Go's `regexp` (RE2, so guaranteed-linear in match time) and then shipped to Envoy. Because RE2 is linear, classic ReDoS doesn't apply.

However:
- There is no upper bound on pattern *length* or *compiled program size*. A 256-KB pattern with thousands of alternations costs O(N) to compile and several MB of RAM per route per Envoy. With M routes, K listeners, you can amplify control-plane and data-plane memory usage.
- `regexp.Compile` itself is *not* linear-time for compilation (it's `O(n^2)` in the worst case for some pathological patterns). The control plane will pay this cost on every reconcile.

**Recommendation:**
Add length caps (e.g., 1024 chars) and reject patterns whose compiled program exceeds an instruction count threshold (`re.NumSubexp()` plus AST node count). Apply via CRD `+kubebuilder:validation:MaxLength=1024` annotations on the regex string fields where the Envoy Gateway controls them (e.g., `RegexHTTPPathModifier.Pattern`).

---

## [MEDIUM] `validateHostname` does not handle IDN / homoglyphs / wildcards consistently
**File:** internal/gatewayapi/validate.go:846-872
**Description:**
The function calls `validation.IsDNS1123Subdomain` and rejects IP addresses but:
- Does **not** punycode-normalize or reject non-ASCII labels. A hostname like `xn--paypal-...` (IDN homoglyph) would be accepted as a valid DNS subdomain and become a listener hostname, enabling homograph attacks for downstream consumers that compare hostnames as strings.
- The total length is not bounded; only per-label is bounded to 63 (which is correct), but the full hostname >253 chars is not rejected. `IsDNS1123Subdomain` does enforce 253, so this is partly mitigated by the upstream check.
- Wildcard handling (`*.example.com`) is delegated to `hostnameMatchesWildcardHostname` (helpers.go:375-382), which uses naive `strings.TrimPrefix(wildcardHostname, "*")` and `len(wildcardMatch) > 0` — it does NOT verify the wildcard match consumes exactly one DNS label. The string "evil.example.com" with wildcard "*.example.com" passes, but so does "evil.attacker.com.example.com" because `len(wildcardMatch) > 0` only checks non-empty.

Actually, re-checking: `strings.HasSuffix(hostname, strings.TrimPrefix(wildcardHostname, "*"))` ensures the suffix matches `.example.com`. So "evil.attacker.com.example.com" *does* match — by spec this is intended for `*.example.com` to match any number of subdomains? Per RFC 6125 the leftmost wildcard matches exactly one label. The current implementation allows multi-label match, contrary to RFC 6125.

**Recommendation:**
- Reject non-ASCII labels in `validateHostname`, or punycode-normalize before validation.
- In `hostnameMatchesWildcardHostname`, ensure `wildcardMatch` contains no '.' (single-label match) to comply with RFC 6125.
- Add tests for `evil.attacker.com.example.com` vs `*.example.com`.

---

## [MEDIUM] HTTP/2 settings: only InitialStreamWindowSize / InitialConnectionWindowSize are range-checked; MaxConcurrentStreams is passthrough
**File:** internal/gatewayapi/http.go:25-76
**Description:**
`MaxConcurrentStreams` is copied directly: `http2.MaxConcurrentStreams = http2Settings.MaxConcurrentStreams` (line 64). Its type is `*uint32`. A user setting `2^31` here would propagate to Envoy and bypass intent-level resource controls. Envoy itself will clamp many of these, but the control plane should validate at least sane upper bounds (e.g., 1M).

This is less critical because Envoy enforces its own caps, but the inconsistency (`InitialStreamWindowSize` is range-checked, `MaxConcurrentStreams` is not) suggests an oversight.

**Recommendation:** add a `+kubebuilder:validation:Maximum=2147483647` (or stricter) to `HTTP2Settings.MaxConcurrentStreams`, and a runtime sanity check that mirrors the other two fields.

---

## [LOW] `EnvoyPatchPolicy.JSONPatches[*].Operation.Value` is `*apiextensionsv1.JSON` with no size limit
**File:** api/v1alpha1/envoypatchpolicy_types.go:114-138
**Description:**
The `Value` field is unbounded `apiextensionsv1.JSON`. Combined with the per-CRD kube-apiserver request size cap (default 3 MiB) and the absence of a `MaxLength`/`MaxItems` annotation on `JSONPatches`, a single EnvoyPatchPolicy can drive a 3 MB blob through the translator on every reconcile. Across N policies this is a memory amplifier.

**Recommendation:** add `+kubebuilder:validation:MaxItems=...` to `JSONPatches` (e.g., 32) and consider a runtime guard that rejects patches whose serialized Value exceeds, e.g., 64 KB.

---

## [LOW] `JSONPatchOperation.Validate()` doesn't catch `Path = ""` (only `Path = nil`)
**File:** internal/ir/xds.go:2640-2677
**Description:**
`IsPathNilOrEmpty()` correctly checks both nil and `EmptyPath`, but `Validate()` only checks `o.Path == nil && o.JSONPath == nil`. A `Path: ""` (empty string) with `JSONPath: nil` passes validation and then `*p.Path` is used at internal/utils/jsonpatch/patch.go:56 — applying a patch at the empty JSON pointer (which means "the root document"). For an `add` op with a non-object Value, this replaces the whole xDS resource. For `remove` it would be even worse.

**Recommendation:**
```go
if (o.Path == nil || *o.Path == "") && (o.JSONPath == nil || *o.JSONPath == "") {
    return fmt.Errorf("a patch operation must specify a non-empty path or jsonPath")
}
```

---

## [LOW] `processListenerSet` mutates a foreign struct field via shared pointer (`ls.Spec.Listeners[i]`)
**File:** internal/gatewayapi/listenerset.go:68-95
**Description:**
```go
for i := range ls.Spec.Listeners {
    listener := &ls.Spec.Listeners[i]
    ...
    gwListener := &gwapiv1.Listener{
        ...
        TLS:           listener.TLS,        // shared pointer into the input object
        AllowedRoutes: listener.AllowedRoutes,
        Hostname:      listener.Hostname,
    }
```
The TLS/AllowedRoutes/Hostname pointers are shared with the input `ListenerSet`. Subsequent translator stages that mutate these (e.g., status writes, defaulting) will write into the input object, which can race with the controller-runtime cache if the input is a non-deep-copied object. Standard controller-runtime usage returns objects from the cache that must not be mutated.

**Recommendation:** deep-copy the listener (or its sub-fields) before storing in the synthesized `gwapiv1.Listener`, or ensure the calling code already deep-copies `ListenerSet` before passing it in.

---

## [LOW] Validator caches a single `Validator` with a mutex, gating concurrent translations
**File:** internal/gatewayapi/resource/validator.go:29-45
**Description:**
`Validate` takes a mutex around `kvalidate.ValidateDocument`. This is not a security bug per se, but every CRD validation in the file-provider path is serialized cluster-wide. For a malicious user submitting many concurrent CRDs (e.g., 10 K small CRs), this becomes a single-threaded bottleneck and amplifies any other DoS attempt. Combined with the synchronous Lua validator (above), this is a meaningful amplifier.

**Recommendation:** evaluate whether kubectl-validate's `Validator` is reentrant; if so, drop the mutex.

---

## [INFO] Dependencies — known-vulnerable libs check
**File:** go.mod
**Description:** versions of historically vulnerable libraries at the time of review:

| Library | Pinned | Known-vulnerable cutoff | Status |
|---|---|---|---|
| `google.golang.org/grpc` | v1.79.1 | <1.59 (rapid reset DoS) | OK |
| `golang.org/x/net` | v0.50.0 | <0.17 (HTTP/2 rapid reset CVE-2023-39325) | OK |
| `golang.org/x/crypto` | v0.48.0 | <0.35 (CVE-2025-22869 SSH bypass) | OK |
| `github.com/go-jose/go-jose/v4` | v4.1.3 | v4.0.x had a parser DoS; v3 had alg confusion historical | OK (on v4 line) |
| `github.com/grpc-ecosystem/grpc-gateway/v2` | v2.27.7 | <2.19 had path traversal | OK |
| `github.com/evanphx/json-patch/v5` | v5.9.11 | <5.6 had stack overflow DoS | OK |
| `github.com/yuin/gopher-lua` | v1.1.1 | (no major CVEs; this is the Lua sandbox engine — see Lua finding) | OK on version |
| `k8s.io/*` | v0.35.1 | most CVEs apply to older minors | OK |
| `helm.sh/helm/v3` | v3.20.0 | <3.14 had repo index DoS | OK |
| `github.com/docker/docker` | v28.5.1+incompatible | <26 had several CVEs | OK |
| `github.com/containers/image/v5` | v5.36.2 | recent | OK |

No `replace` directives are present in go.mod. **No directly known-vulnerable versions detected.** Note: indirect deps like `go.podman.io/storage`, `github.com/containerd/containerd v1.7.30`, etc. depend on patch level — recommend running `govulncheck ./...` as part of CI.

---

## [INFO] EnvoyExtensionPolicy and EnvoyPatchPolicy gating reviewed
**File:** internal/gatewayapi/envoypatchpolicy.go, internal/gatewayapi/envoyextensionpolicy.go
**Description:** Both have feature-flag gates (`EnvoyPatchPolicyEnabled` and `LuaEnvoyExtensionPolicyDisabled`). When EnvoyPatchPolicy is disabled, translation rejects the policy with `PolicyReasonDisabled` (line 69-82). Lua features similarly. These flags are the primary defense; see the HIGH-severity finding above for why this is insufficient.

---

## [INFO] Reviewed, no issues found
- **Hostname-tuple key construction (`validateConflictedMergedListeners`, validate.go:685-705):** uses `new(gwapiv1.Hostname)` to handle nil Hostname; safe.
- **`validateBackendRefService` Port deref (validate.go:185-209):** preceded by `validateBackendPort` which guarantees non-nil for Service kind.
- **`jsonpatch.ApplyJSONPatches` (internal/utils/jsonpatch/patch.go):** calls `p.Validate()` per-operation; errors aggregated rather than fatal.
- **`infra.go` Validate (`ProxyInfra.Validate`):** ports range-checked 1..MaxPort.
- **Regex compilation sites (filters.go:73, 831):** package-level patterns are constants; user regex compilation only checks syntax (RE2 is linear at match time, so ReDoS in Envoy is bounded).
- **`strconv.Atoi` only one site (securitypolicy.go:1712):** parses `parsedURL.Port()`, error-checked.
- **`SkipOpenLibs: false` in Lua state:** intentional — `mocks.lua` needs `setmetatable`; covered (and largely mitigated) by `security.lua`. See Lua HIGH finding for residual issues.
- **`IncludeGoStackTrace: false`:** correct, prevents leaking controller paths/symbols to user error messages.
- **`io.popen = nil; os.execute = nil` in security.lua:** correctly removed; gopher-lua honors these nullifications.

---

## Summary table

| Severity | Count |
|---|---|
| HIGH | 3 |
| MEDIUM | 5 |
| LOW | 3 |
| INFO | 3 |

Top three priorities:
1. Either restrict EnvoyPatchPolicy to cluster-admin via `ClusterScoped` CRD or add admission-time field-allowlisting.
2. Fix the Lua sandbox: nil `getfenv`/`setfenv`/`coroutine`, add memory caps, change default to `SyntaxOnly`.
3. Fix the nil-pointer panic in `listener.go:68` on `*listener.TLS.Mode`.
