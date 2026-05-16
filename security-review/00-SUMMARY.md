# Envoy Gateway — Security Review (consolidated)

Branch reviewed: `claude/review-envoy-security-euKRi` @ commit `ae25790`
Scope: full codebase sweep (371 non-test Go files, ~88k LOC).

Six parallel reviewers covered: crypto/TLS, authN/Z (JWT/OIDC/BasicAuth/APIKey/ExtAuthz/CORS), xDS server + Envoy config generation, control-plane interfaces (admin/webhooks/extensions/metrics/troubleshoot), WASM/SSRF/fetchers/infrastructure, and input validation/IR/dependencies.

Per-area reports: `01-crypto.md`, `02-auth.md`, `03-xds.md`, `04-control-plane.md`, `05-fetchers-infra.md`, `06-validation-ir.md`.

---

## Severity tally

| Severity | Count |
|----------|-------|
| HIGH     | 18    |
| MEDIUM   | 26    |
| LOW      | 21    |
| INFO     | 17    |

---

## Top 10 — fix first

These are the issues with the highest exploitability + impact, ranked.

### 1. Default-mode cross-gateway snapshot impersonation (data-plane → arbitrary tenant xDS)
**File:** `internal/xds/cache/snapshotcache.go:159-168, 209-247, 327-393`
Outside `GatewayNamespaceMode`, every Envoy pod uses the same shared mTLS client cert. The xDS cache partitions snapshots by client-supplied `node.Cluster` with **no check that the presented cert is authorized for the requested cluster**. A compromised Envoy in one tenant (or any pod that can mount the `envoy` secret) sets `node.Cluster` to another gateway's IR key and receives the full snapshot — including inline TLS private keys (SDS), OIDC client secrets, BasicAuth files, credential-injector tokens. Multi-tenant deployments without `GatewayNamespaceMode` are effectively single-trust.
**Fix:** Bind mTLS cert identity (SAN/CN/SPIFFE) to an allowed `node.Cluster` set. Loudly document that `GatewayNamespaceMode` is required for multi-tenant isolation.

### 2. JWT xDS auth bypass in GatewayNamespaceMode
**File:** `internal/xds/server/kubejwt/tokenreview.go:62-71`
Pod-name binding is inside `if tokenReview.Status.User.Extra != nil`. Non-projected SA tokens (legacy long-lived tokens, `kubectl create token` without `--bound-object-ref`) → **binding silently skipped**, so any cluster SA membership in `system:serviceaccounts` authenticates as any node. Same line dereferences `podName[0]` with no length check → panic vector.
**Fix:** Require non-nil Extra + non-empty podName. Validate audience.

### 3. EnvoyPatchPolicy = cluster-admin via namespaced CRD
**File:** `internal/gatewayapi/envoypatchpolicy.go:20-119`, `api/v1alpha1/envoypatchpolicy_types.go`
Once the global feature flag is on, `create envoypatchpolicies` in any gateway namespace lets the author inject arbitrary Envoy config: drop TLS, swap certs, install `lua`/`ext_authz` filters that bypass the in-controller Lua validator entirely, rewrite cluster transport sockets to disable backend cert verification. The CRD godoc admits this; nothing enforces it.
**Fix:** Make CRD `ClusterScoped`, or add admission-time field allowlisting (forbid patches that touch `transport_sockets`, `tls_certificates`, `validation_context`, add `lua`/`wasm`/`ext_authz` filters not in base config, patch Secret xDS type at all). At minimum, gate with `AllowedPatchPolicyNamespaces []string` in EnvoyGateway config.

### 4. Lua sandbox escape via `getfenv`/`setfenv` (controller-side code exec)
**File:** `internal/gatewayapi/luavalidator/security.lua:102-117`, `lua_validator.go:97-115`
Sandbox nils `_G` but leaves gopher-lua's `getfenv`/`setfenv` (Lua 5.1) intact. `getfenv(0)` recovers the globals table. `coroutine` not nilled. `string.rep("A", 1<<28)` allocates ~256 MB in-controller. `defer recover()` catches Go panics — not OOMKill. **Strict mode is the default**, so every EnvoyExtensionPolicy executes user Lua in the controller. RBAC creator → controller compromise / OOM-killable.
**Fix:** Nil `getfenv`/`setfenv`/`coroutine`. Cap `string.rep`. Default to `SyntaxOnly`. Run Strict validation out-of-process with `setrlimit`/cgroup limits.

### 5. SSRF in Wasm fetch + OIDC discovery (control plane → IMDS / kubelet / internals)
**Files:** `internal/wasm/httpfetcher.go:87-128`, `cache.go:245-256`; `internal/gatewayapi/securitypolicy.go:1593-1648`
No host/IP validation, no DNS-rebinding protection, no `CheckRedirect`. Any user who can author an `EnvoyExtensionPolicy` (Wasm URL) or `SecurityPolicy` (OIDC issuer) can have the control plane GET `http://169.254.169.254/...` (cloud IMDS), kubelet `:10250`, internal services. `validateTokenEndpoint` rejects IPv4 literals only; IPv6 + hostnames-resolving-to-private slip through. OIDC discovery decodes JSON with no `LimitReader` → giant-body OOM.
**Fix:** Allowlist/denylist hostnames+IPs, resolve-once-then-dial-IP via custom `net.Dialer.Control`, cap redirects, `io.LimitReader` on the body. Apply to OIDC issuer, JWKS, ext_authz, Wasm.

### 6. JWT RemoteJWKS and OIDC Issuer accepted over plaintext HTTP → full auth bypass
**Files:** `internal/gatewayapi/securitypolicy.go:1112, 1176-1185, 1423-1438, 1614-1615`; `internal/xds/translator/utils.go:81`
`validateJWTProvider` calls `url.ParseRequestURI` and accepts `http://...`; cluster is built without TLS. Attacker controlling DNS / on-path serves attacker public keys → forges any JWT. OIDC `/.well-known/openid-configuration` over HTTP lets attacker dictate authorization/token/end-session endpoints → full OIDC takeover. CRD docs say "MUST be https" but no validation enforces it.
**Fix:** Require `https://` scheme in `validateJWTProvider`, `validateOIDCProvider`, and via CRD `XValidation`. Same for `tokenEndpoint`/`authorizationEndpoint`/`endSessionEndpoint`.

### 7. WASM supply chain: no signature verification, `:latest` auto-appended, `InsecureRegistries: "*"` accepted
**Files:** `internal/wasm/cache.go:286-308`, `imagefetcher.go:80-88, 140-169`, `envoyextensionpolicy.go:1062`, `options.go:51`
SHA256 is optional; when absent, any binary the registry returns is accepted ("Update the checksum with the one from the downloaded binary"). No cosign / Notary. Three OCI media types tried with silent fallthrough. `InsecureRegistries` accepts `*` wildcard turning off TLS verification for every host. Default Envoy image pinned by mutable tag, not digest.
**Fix:** Require SHA256 when no digest in URL. Add cosign verification opt-in. Reject `*` in `InsecureRegistries`. Pin default image by digest.

### 8. Tar header `h.Size` used to allocate + decompression bombs
**Files:** `internal/wasm/imagefetcher.go:274, 329-334`; `internal/wasm/httpfetcher.go:176, 188-201`
`ret := make([]byte, h.Size)` uses attacker-controlled tar header size before any read → allocate 1 EB → OOM panic. `io.ReadAll(zr)` on gzip with no decompressed-size cap (compressed input bounded to 256MB; decompresses to TB). `io.ReadAll(layer.Compressed())` in OCI artifact path with no cap at all. Single malicious image → control-plane OOM kill → cluster-wide xDS outage.
**Fix:** Reject `h.Size < 0 || h.Size > maxWasmSize` before `make`. Wrap decompressors in `io.LimitReader(_, maxWasmSize)`.

### 9. Extension gRPC defaults to plaintext + no per-call timeout
**File:** `internal/extension/registry/extension_manager.go:299-322`, `xds_hook.go:55-57,79-81,...`
When `EnvoyGateway.ExtensionManager.Service.TLS` is nil, dial uses `insecure.NewCredentials()` — full xDS table flows over plaintext. Combined with **no timeout** (`context.Background()` on every hook RPC), a hung or malicious extension server stalls the entire xDS pipeline for all gateways. The extension's response is merged into xDS with no validation — privilege equivalent to EG itself.
**Fix:** Require TLS by default or explicit `AllowPlaintext`. Add `context.WithTimeout` (default 5s, configurable). Document extension trust = EG trust.

### 10. Bootstrap YAML template injection via OTel sink fields
**Files:** `internal/xds/bootstrap/bootstrap.yaml.tpl:80-104, 217-237`; `internal/infrastructure/common/proxy_metrics.go:14-44`
Bootstrap rendered with `text/template` (not `html/template`); OTel `Headers[].Name/Value`, `ResourceAttributes` keys/values, `Authority`, `SNI`, `Address` come from `EnvoyProxy` CRD and are interpolated **unquoted/unescaped**. A header value of `"x\nadditional_field: malicious"` injects arbitrary bootstrap fields (stats sinks, runtime layers, admin listener changes). `BuildProxyArgs` passes the rendered YAML straight to Envoy via `--config-yaml` — no re-validation of generated baseline.
**Fix:** Parse the rendered bootstrap as `bootstrapv3.Bootstrap` proto and `Validate()` before passing to Envoy. Or switch to YAML encoder for all interpolated fields. At minimum, reject `\r\n` / `:` in OTel header/attribute strings at IR build time.

---

## Other HIGH-severity issues (8)

These are real and exploitable; group #2 below the headliners above.

- **Predictable cert serial numbers** — `internal/crypto/certgen.go:272-274`. `time.Now().Nanosecond()` gives ~30 bits; CA + leaves often cluster within microseconds. RFC 5280 wants ≥64 bits CSPRNG.
- **Host-mode private keys written `0o644`** — `internal/utils/file/file.go:16` writes `tls.key` + OIDC HMAC seed world-readable in `certgen --local` and `maybeGenerateCertificates` paths.
- **LocalJWKS ConfigMap "first key" fallback is non-deterministic** — `securitypolicy.go:1231-1240`. Go-map iteration order picks an arbitrary value; adding any benign key (`README.md`) silently swaps the JWKS used.
- **Wasm HTTP server data race on `mappingPath2Cache`** — `internal/wasm/httpserver.go:148-157, 199-208`. `ServeHTTP` reads the map without lock while `Get()` writes under it → panic crash.
- **Wasm-serving HTTP server "auth" = `sha256(URL || OIDC-HMAC-secret)`** — any in-cluster pod that can read the OIDC HMAC secret can enumerate every cached Wasm module.
- **Troubleshoot bundle dumps all ConfigMaps verbatim** — `internal/troubleshoot/collect/troubleshoot_helper.go:582-621`. CMs frequently carry PEM CAs, HMAC keys, tokens. No redaction.
- **`xdsStreamDurationSeconds` metric uses unbounded `streamID` label** — `internal/xds/cache/metrics.go:21-29`. Cardinality grows linearly with reconnects → metric memory + scrape blowup.
- **Nil deref on `*listener.TLS.Mode`** — `internal/gatewayapi/listener.go:68`. Single TLS listener with no `mode` (defaulting bypass via file provider or older API server) crashes the translator goroutine → control-plane outage.

---

## Notable MEDIUMs to fix soon

- **EnvoyProxy `Patch` escalation** (`internal/utils/merge.go`, `resource_provider.go:308,449,520,607`). Namespaced CR; patch is unvalidated → any author can set `privileged: true`, `hostNetwork: true`, `hostPath: /`, swap image, override SA. Effectively "EnvoyProxy write = node root". Document loudly; consider built-in deny-list for those fields.
- **Default RBAC grants cluster-wide secrets read** (`charts/gateway-helm/templates/_rbac.tpl:31-42`). Compromise of EG pod = read every Secret cluster-wide. Strongly recommend `Watch.Namespaces` in production.
- **Metrics endpoint binds `0.0.0.0:19001` with no auth** (`api/v1alpha1/envoygateway_types.go:23-26`). Default to `127.0.0.1` or document.
- **JWT claim-to-headers spoof when `Optional=true`** — `jwt.go:119-220`. Claims-to-header *appends*; pre-existing client headers aren't stripped. Optional JWT + claim-to-header → client sets `X-User: admin`.
- **CORS `AllowCredentials=true` with wildcard origin** — `securitypolicy.go:993-1024`, `cors.go:167`. `*` regex full-matches any origin and is echoed back, bypassing the browser's wildcard+credentials block.
- **CORS wildcard regex not label-bounded** — `wildcard2regex` produces `.*` from `*`; `*.example.com` matches `evil.attacker.com.example.com`.
- **ExtAuth `FailOpen=true` masks build-time policy errors** — `securitypolicy.go:736-744`. The translator *skips* the 500 direct response when only ExtAuth fails. Config errors silently disable auth.
- **OIDC `DisableTokenEncryption` / `SameSite=None` / plaintext `ClientID`** — no warning, no admission guardrail.
- **Response header CRLF check missing on ResponseOverride/DirectResponse** — `backendtrafficpolicy.go:1781,1788`, `filters.go:911,922,929`. HeaderValueRegexp is enforced on `RequestHeaderModifier`/`ResponseHeaderModifier` but not these.
- **JWKS/OIDC upstream clusters missing `AutoSniSanValidation`** — `internal/xds/translator/jwt.go:242-269`. Any cert from any trusted CA can impersonate JWKS / OIDC endpoint.
- **Lua validator default = Strict** — executes every submitted Lua chunk inside the controller for up to 5s × 2 sides = 10s per policy.
- **No `MaxConcurrentStreams` / `MaxRecvMsgSize` on xDS gRPC server** — `internal/xds/runner/runner.go:175-210` and `internal/globalratelimit/runner/runner.go:92`. Default `MaxConcurrentStreams = math.MaxUint32`.
- **Extension `MaxMessageSize` uncapped** — operator can set 16 GB.
- **OIDC `validateTokenEndpoint` rejects IPv4 only** — IPv6 (`http://[::1]/token`) and resolved-to-private hostnames pass.
- **Token-endpoint validator + OIDC HMAC never rotates** — keys signing session cookies are durable on compromise.
- **Lua nil-deref on `lua.Inline == nil`** — `internal/gatewayapi/envoyextensionpolicy.go:735`.
- **`*ref.Port` nil-deref in file-provider** — `internal/gatewayapi/resource/load.go:626`.
- **Hostname validator doesn't reject IDN homoglyphs; wildcard match allows multi-label match contrary to RFC 6125** — `internal/gatewayapi/validate.go:846-872`, `helpers.go:375-382`.
- **HTTP2 `MaxConcurrentStreams` passthrough with no range check** — `internal/gatewayapi/http.go:25-76`.
- **Troubleshoot CR collector dumps EnvoyPatchPolicy inline JSON** — may contain inline credentials.
- **OCI `Insecure` mode lacks `tls.MinVersion`** — bearer token sent over potentially TLS 1.0.
- **`InsecureSkipVerify` for OIDC discovery via `ToTLSConfig`** — silently honored on the control-plane HTTP client; no default `MinVersion`.

---

## Reviewed-clean (no issues found)

These were checked thoroughly and look correct:

- TLS minimum versions on the EG control-plane (1.3 pinned for xDS server).
- mTLS config on xDS server (`RequireAndVerifyClientCert`, cert reload via `GetConfigForClient`).
- Cross-namespace secret refs for security policies (`allowCrossNamespace=false`, ReferenceGrant enforced on BackendRefs).
- ReferenceGrant enforcement for Gateway-API CR cross-namespace refs.
- HMAC secret generation (32 bytes from `crypto/rand`).
- Admission webhook hardening (mTLS, `failurePolicy=Ignore`, `sideEffects=None`).
- Default Pod security context (drop all caps, no privilege escalation, RuntimeDefault seccomp).
- ServiceAccount `AutomountServiceAccountToken: false` on Envoy proxy pods.
- `ir.PrivateBytes` redacts secrets on log/JSON marshal.
- `regexp.QuoteMeta` used on user prefix→regex paths to prevent regex injection.
- `RequestHeaderModifier`/`ResponseHeaderModifier` header name/value validation (CRLF rejected).
- Authorization (RBAC) translation: deny-by-default correct.
- Envoy oauth2 filter handles PKCE/state/nonce internally.
- Constant-time credential comparisons (delegated to Envoy filters).
- No directly known-vulnerable dependency versions in go.mod.
- No `unsafe` or `cgo` shenanigans found in scope.
- JSONPatch translator re-validates each resource via `proto.Validate()` after patching.

---

## Caveats

This review is automated static-analysis-style; it has not exercised running code or fuzzed inputs. Several findings (especially the SSRF/decompression-bomb/tar-header items) deserve confirmatory PoCs before disclosure. The xDS multi-tenant snapshot leak (#1) and the JWT pod-binding bypass (#2) are the highest-confidence vulnerability claims and worth raising with the Envoy Gateway security team via their `SECURITY.md` channel.
