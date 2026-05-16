# Security review: xDS server, Envoy config generation, IR translation

Scope: `internal/xds/server`, `internal/xds/cache`, `internal/xds/translator`, `internal/xds/bootstrap`, `internal/xds/filters`, `internal/xds/runner`, `internal/ir`, `internal/globalratelimit`. Method as described in the brief; key files read end-to-end: `runner.go`, `snapshotcache.go`, `bootstrap.go`, `bootstrap.yaml.tpl`, `validate.go`, `util.go`, `translator.go`, `route.go`, `lua.go`, `wasm.go`, `custom_response.go`, `header_mutation.go`, `jsonpatch.go`, `jwtinterceptor.go`, `tokenreview.go`, `crypto/cert_load.go`, plus targeted reads of `listener.go`, `cluster.go`, `ratelimit.go`, `oidc.go`, `jwt.go`, `proxy_args.go`, `proxy_metrics.go`, `gatewayapi/filters.go`, `gatewayapi/clienttrafficpolicy.go`, `gatewayapi/backendtrafficpolicy.go`, `gatewayapi/listener.go`, `gatewayapi/helpers.go`.

---

## 1. xDS server hardening

## [HIGH] xDS server JWT interceptor silently skips pod-binding check when TokenReview "Extra" map is nil
**File:** /home/user/gateway/internal/xds/server/kubejwt/tokenreview.go:62-71
**Description:** When `GatewayNamespaceMode` is enabled, the xDS gRPC server uses a JWT interceptor that calls Kubernetes TokenReview and is expected to bind a given mTLS/SA token to a single node ID (pod name). The current implementation only performs the binding check inside `if tokenReview.Status.User.Extra != nil`. If `Extra` is nil — which happens whenever the presented token is not a projected/bound service-account token (e.g., legacy long-lived SA tokens, or tokens minted with `kubectl create token` without `--bound-object-ref`) — the entire pod-name check is skipped. The function then returns `nil` and the caller treats the request as authenticated for ANY node ID, allowing one compromised Envoy pod (or any client with any SA token whose `system:serviceaccounts` membership passes line 52) to fetch the xDS snapshot — including TLS private keys in SDS secrets — of any other Envoy pod managed by the same control plane. The companion code at line 64 also indexes `podName[0]` without checking `len(podName) > 0`, leading to a panic / DoS if the key is present but the slice is empty.
**Recommendation:** Make the pod-name binding mandatory: if `Extra == nil` or `Extra[PodNameKey]` is empty/missing, return an error. Add `len(podName) > 0` check before `podName[0]`. Also reject tokens whose `Audiences` (returned by the TokenReview) does not contain exactly the expected audience (defense in depth).

## [HIGH] Default deployment mode: any holder of the shared xDS client cert can receive any gateway's xDS snapshot (including TLS private keys)
**File:** /home/user/gateway/internal/xds/cache/snapshotcache.go:159-168 (getNodeIDs), :209-247 (OnStreamRequest), :327-393 (OnStreamDeltaRequest)
**Description:** Outside `GatewayNamespaceMode`, the only authentication on the xDS gRPC server is mTLS using one CA + one client cert shared across ALL Envoy proxy pods (`internal/crypto/cert_load.go` requires `ClientAuth: tls.RequireAndVerifyClientCert` with the EG-minted CA, and the same `envoy-gateway` secret is mounted into every Envoy pod). The control plane partitions snapshots per `node.Cluster` (set via `--service-cluster` arg), and `OnStreamRequest` accepts any value the client supplies in its `DiscoveryRequest.Node`. There is no check that the cert presented at the TLS layer is authorized for the requested `node.Cluster` / `node.Id`. Therefore any pod that can reach port 18000 with the shared client cert (e.g., a compromised Envoy in one tenant, or any pod mounting the `envoy` secret) can set `node.Cluster` to another gateway's IR key and receive that gateway's full xDS state — which includes inline TLS private keys (`buildXdsTLSCertSecret` in listener.go, OIDC client secrets, basic-auth user files, credential-injector tokens, etc.). The threat model effectively requires `GatewayNamespaceMode` for cross-gateway isolation, but this is not the default and is not loudly documented as a security requirement.
**Recommendation:** Document clearly that, without `GatewayNamespaceMode`, all Envoy pods share trust over all gateway-scoped secrets, and recommend `GatewayNamespaceMode` for any multi-tenant deployment. Better: bind the mTLS client identity (cert SAN or CN, or SPIFFE ID) to an authorized `node.Cluster` set, and reject requests whose `node.Cluster` is not in the allowed set for the presented certificate. Even with GatewayNamespaceMode, fix Finding 1 first.

## [MEDIUM] xDS gRPC server has no max-receive-message-size or max-concurrent-streams limit
**File:** /home/user/gateway/internal/xds/runner/runner.go:175-210
**File:** /home/user/gateway/internal/globalratelimit/runner/runner.go:92
**Description:** `grpc.NewServer(grpcOpts...)` is constructed with only `KeepaliveEnforcementPolicy`, `KeepaliveParams`, and TLS creds (plus optional JWT interceptor). No `grpc.MaxRecvMsgSize`, `grpc.MaxSendMsgSize`, `grpc.MaxConcurrentStreams`, `grpc.MaxHeaderListSize`, `grpc.ConnectionTimeout`, or `grpc.InitialWindowSize` / `grpc.InitialConnWindowSize` are configured. The gRPC default max-receive is 4 MiB, which limits per-message attacks, but `MaxConcurrentStreams` defaults to `math.MaxUint32`, allowing a single authenticated Envoy peer (or anyone past the mTLS perimeter) to open millions of HTTP/2 streams to exhaust memory. The same applies to the global-rate-limit gRPC server.
**Recommendation:** Set `grpc.MaxConcurrentStreams(100)` (or a sane number — Envoy only needs a handful), explicit `grpc.MaxRecvMsgSize`, and `grpc.ConnectionTimeout`. Add the same options on `internal/globalratelimit/runner/runner.go:92`.

## [INFO] xDS server binds to 0.0.0.0 by default
**File:** /home/user/gateway/internal/xds/runner/runner.go:48-49
**Description:** `XdsServerAddress = "0.0.0.0"`. In Kubernetes the surrounding NetworkPolicy / Service definition is expected to restrict reachability to the EG service ClusterIP. Combined with mTLS this is the standard control-plane design, but on Host (non-K8s) deployments, the port is exposed on every interface unless the operator firewalls it. Worth documenting.
**Recommendation:** Allow operators to override the bind address (e.g., to `127.0.0.1` in single-node host mode) via `EnvoyGateway.XDSServer`.

## [INFO] gRPC keepalive randomization uses non-cryptographic RNG
**File:** /home/user/gateway/internal/xds/runner/runner.go:142-145
**Description:** `getRandomMaxConnectionAge` uses `math/rand` (`//nolint:gosec`). Used only for load-balancing across EG replicas, not for authentication, so non-issue from a security perspective; leaving as INFO.
**Recommendation:** No change needed; document as non-security.

## Reviewed, no issues
- mTLS default config is strong: TLS 1.3 only, `RequireAndVerifyClientCert`, CA pinned via `ClientCAs` (`internal/crypto/cert_load.go:35-56`).
- `GetConfigForClient` callback reloads certs per handshake (supports rotation without restart).
- Stream forced-stop on context done uses `grpc.Stop()` (not `GracefulStop`) by design — documented in code (runner.go:235-240).

---

## 2. Bootstrap template / Envoy config injection

## [MEDIUM] Bootstrap YAML template interpolates CRD-supplied OTel-sink fields without quoting/escaping
**File:** /home/user/gateway/internal/xds/bootstrap/bootstrap.yaml.tpl:80-104, :217-237
**File:** /home/user/gateway/internal/xds/bootstrap/bootstrap.go:61-65 (template constructor)
**File:** /home/user/gateway/internal/infrastructure/common/proxy_metrics.go:14-44 (CRD → bootstrap parameters)
**Description:** Bootstrap is rendered with `text/template` (not `html/template`) and several values that ultimately come from `EnvoyProxy` CRD fields are interpolated without YAML escaping:
- `{{ $sink.Authority }}` (line 81) — derived from SNI/hostname/Service metadata
- `{{ .Name }}` / `{{ .Value }}` for OTel `Headers` (lines 86-87)
- `{{ $key }}: "{{ $value }}"` for `ResourceAttributes` (line 103)
- `{{ $sink.Address }}`, `{{ $sink.Port }}` (lines 217-218) — address from CRD/backend
- `{{ $sink.TLS.SNI }}` (line 225)
- `{{ .ServiceClusterName }}` (lines 13, 246, 256) — derived from `<namespace>/<name>` but only namespace+name normally; the test path allows overrides.
- `{{ .AdminServer.AccessLogPath }}` (line 6) — could be overridden.

A header value containing a newline (e.g., `Header.Value = "x\nadditional_field: malicious"`) would inject arbitrary fields into the rendered bootstrap. The bootstrap is passed to Envoy via `--config-yaml` (`internal/infrastructure/common/proxy_args.go:73`), so an attacker who can write `EnvoyProxy` resources with arbitrary OTel headers/resource-attributes can craft Envoy bootstrap stanzas (stats sinks, runtime layers, listener-trusting CA, admin listener changes, etc.).

Note that `bootstrap.Validate` (validate.go:52-89) is called only against the user-supplied `ProxyBootstrap` JSON patch/merge, NOT against the rendered output for non-bootstrap CRD inputs (OTel headers etc.) — and `BuildProxyArgs` does NOT re-parse / re-validate the final rendered YAML before passing it to Envoy. CRD CEL validation on `EnvoyProxy.Spec.Telemetry.Metrics.Sinks.OpenTelemetry.Headers[].Value` is the upstream Gateway-API `HTTPHeader` type whose `value` field uses pattern `^.+$` (no newline restriction).
**Recommendation:** Either (a) parse the rendered bootstrap as protobuf via `bootstrapv3.Bootstrap` and re-validate before passing to Envoy (already done for user bootstrap patches; extend to all paths) — this will fail-closed on YAML-injected attempts; or (b) switch the template to emit strict YAML using a templated marshaller (`gopkg.in/yaml.v3` encoder); or (c) at minimum, wrap every CRD-derived field in `{{ ... | quote }}` (a custom function that JSON-encodes the string, which is valid YAML), and reject any header name/value/SNI/authority containing `\r`, `\n`, `:`, or other YAML metacharacters at IR build time. Note `{{js $item}}` is used at line 45 for stats matchers, but everywhere else interpolation is bare.

## [LOW] Bootstrap template does not reject template-control characters in `ServiceClusterName`
**File:** /home/user/gateway/internal/xds/bootstrap/bootstrap.yaml.tpl:13, 246, 256
**File:** /home/user/gateway/internal/infrastructure/common/proxy_args.go:36-42
**Description:** `serviceCluster` is built from `infra.Namespace`/`infra.Name`; K8s namespace/name validation prevents `/`-injection but allows `.`, `-`, etc. Not exploitable today because the kubernetes naming rules are strict (lowercase RFC 1123) so this is more of a defense-in-depth note.
**Recommendation:** Quote the value in the template with the same `quote` function suggested above; treat all template inputs as untrusted.

## Reviewed, no issues
- Only `text/template` use under `internal/` is bootstrap; no other YAML/HTML template rendering of CRD inputs found.
- User-supplied `ProxyBootstrap` (`merge`/`replace`/`jsonPatch`) is parsed + validated as `bootstrapv3.Bootstrap` proto and rejected if it touches `dynamic_resources` or `xds_cluster.load_assignment` (`internal/xds/bootstrap/validate.go:64-87`).
- gRPC `RateLimit` config emission is via YAML encoder (`ratelimit.go:540-557`), not text template — safe.

---

## 3. Filter / route translators (injection from CRDs)

## [MEDIUM] Response headers in BackendTrafficPolicy `ResponseOverride` and HTTPRouteFilter `DirectResponse` bypass HeaderValue RFC-7230 regex check
**File:** /home/user/gateway/internal/gatewayapi/backendtrafficpolicy.go:1778-1794
**File:** /home/user/gateway/internal/gatewayapi/filters.go:893-935 (DirectResponse), :908-913 (Content-Type from DirectResponse)
**Description:** Response headers added via Gateway API `HTTPRouteFilter` `RequestHeaderModifier`/`ResponseHeaderModifier` are validated against `HeaderValueRegexp = ^[!-~]+([\t ]?[!-~]+)*$` (`internal/gatewayapi/filters.go:73`) which rejects CR/LF/control chars. However, the equivalent header lists on `BackendTrafficPolicy.Spec.ResponseOverride.Response.Header.Add/Set` and on `HTTPRouteFilter.Spec.DirectResponse.Header.Add/Set` and on `HTTPRouteFilter.Spec.DirectResponse.ContentType` are copied verbatim into `ir.AddHeader{Value: [...]}` without any regex/CRLF check. They then flow into the Envoy route config (`buildXdsAddedHeaders` in `route.go:636-679`).

Envoy 1.27+ does reject `\r`/`\n` in header values at encode time (and silently drops them in some HTTP/2 paths), so the practical exploitability of HTTP response splitting against downstream clients is currently low. But the lack of input validation is inconsistent with other paths and provides no defense if Envoy ever loosens header validation. Authors with permission only to `BackendTrafficPolicy`/`HTTPRouteFilter` can also set duplicated `Content-Type` etc.
**Recommendation:** Apply `HeaderValueRegexp.MatchString` (and the `:`/`/` name check) to all of the following code paths and reject offending entries with a status condition: `backendtrafficpolicy.go:1781,1788`; `filters.go:911,922,929`. Consider also stripping the values to single-line ASCII at the `ir.AddHeader.Validate()` level for defense-in-depth, since that is the single chokepoint just before xDS translation.

## [LOW] ResponseOverride / DirectResponse body has no upstream size cap; xDS translator dynamically raises Envoy's max-direct-response-body size to actual body length
**File:** /home/user/gateway/internal/xds/translator/translator.go:484-490, :674-683
**File:** /home/user/gateway/internal/gatewayapi/backendtrafficpolicy.go:1809-1846 (getCustomResponseBody)
**Description:** `getCustomResponseBody` reads body bytes verbatim from inline string or `ConfigMap.Data[...]`. The translator (line 547) tracks the maximum length across all routes and (lines 678-682) sets `route_configuration.max_direct_response_body_size_bytes` to that value, clamped to at least `DefaultCRDMaxSize = 1 MiB`. There is no upper bound — if a body > 1 MiB is supplied (e.g., from a manually constructed ConfigMap, or via `inline: <huge string>` if CRD size limits aren't applied), the translator will set Envoy's per-route max body size to the actual size. Each Envoy worker thread must keep the body in memory for the route config. Many large direct-response routes can multiply this. Combined with no count cap on routes, this is a memory amplification vector for a tenant with HTTPRoute/BackendTrafficPolicy write access.
**Recommendation:** Cap the body size at IR-build time (e.g., 1 MiB hard cap from `getCustomResponseBody` regardless of source) and report a status condition if exceeded.

## [INFO] EnvoyExtensionPolicy `Lua` executes operator-supplied Lua inside the data-plane (by design)
**File:** /home/user/gateway/internal/xds/translator/lua.go:60-89
**Description:** The `lua.Code` IR string is dropped directly into `envoy.filters.http.lua` `DefaultSourceCode.InlineString`. This is the documented purpose of the feature. The Lua filter runs inside the Envoy worker thread with full access to all request data, the streaminfo metadata, the upstream cluster connection and the `httpCall` API (cross-cluster requests through Envoy). It is sandboxed by the Envoy LuaJIT runtime but has no further sandboxing (no read-only memory, can issue arbitrary HTTP calls within Envoy's clusters, can `error()` to fail requests, etc.). An IR-side validator (`internal/gatewayapi/luavalidator/lua_validator.go`) checks that the code compiles and defines `envoy_on_request`/`envoy_on_response`, but does not restrict the API surface.
**Recommendation:** This is by-design. Document clearly that `EnvoyExtensionPolicy.spec.lua` should only be granted to operators trusted at the same level as the data-plane configuration. Consider RBAC guidance and/or a feature flag to disable the Lua filter cluster-wide.

## [INFO] EnvoyExtensionPolicy `Wasm` fetches modules over HTTP from CRD-supplied URLs; server-side validation is shallow
**File:** /home/user/gateway/internal/xds/translator/wasm.go:101-158
**Description:** `wasm.Code.ServingURL` is taken from the IR and inserted into the Envoy `RemoteDataSource.HttpUri.Uri`. There is a SHA256 pin (`wasm.Code.SHA256`) which mitigates tampering of the binary in flight, but the fetch URL is not validated against an allowlist on the control-plane side (apart from the IR-build code that proxies through EG's internal HTTP server). Envoy is the one issuing the GET, so any SSRF goes from Envoy worker → wasm-cluster, not from EG → URL. Listed as INFO since it's the documented model.
**Recommendation:** Document the trust model. Consider letting operators allowlist hostname patterns at the `EnvoyGateway` level.

## Reviewed, no issues
- Redirect translation (`route.go:440-483`) validates Scheme (`http`/`https` only, `xds.go:1995-1999`) and StatusCode (`301`/`302` only, `xds.go:2007-2011`).
- URLRewrite host/path/regex translation copies through protobuf (`route.go:505-577`), with `regexp.QuoteMeta` on prefix substitutions to prevent regex-injection (line 499).
- AddHeader name/value for `HTTPRouteFilter.RequestHeaderModifier`/`ResponseHeaderModifier` go through `HeaderValueRegexp` (`gatewayapi/filters.go:474,527,651,704`) and a `/` / `:` reject (`isModifiableHeader`).
- BasicAuth users-file, OIDC client/HMAC secret, credentialInjection credential are read from `Secret` and inserted as `InlineBytes` (not strings) into proto messages — no template-rendering involved.
- `regex.Validate` is called for any operator-supplied regex used in stats matchers (`bootstrap.go:293`) and elsewhere.
- Direct-response body and HCM filter configs are inserted via proto `InlineBytes` / `TypedConfig` — no YAML/text templating.
- JSONPatch translator (`jsonpatch.go`) unmarshals each patched resource back into typed protobuf and validates (`temp.Validate()`) before merging, so patch-induced invalid configs cannot poison the snapshot.

---

## 4. Translator resource-exhaustion / IR processing

## [LOW] Translator iterates over CRD-controlled slices without upper bounds
**File:** /home/user/gateway/internal/xds/translator/translator.go:271-481 (HTTP listener loop), :510-680 (route loop), :760-878 (TCP loop), :883-940 (UDP loop)
**Description:** All `for _, listener := range httpListeners` / `for _, route := range httpListener.Routes` etc. are unbounded; if a user creates a Gateway with thousands of HTTPRoutes (each with hundreds of rules), each `Translate` call allocates O(routes × policies) protobuf messages, then validates with `tCtx.ValidateAll()` which is also linear. No CPU/memory cap is applied. The Translator is best-effort and accumulates `errs`, so it will not bail out early on an attack input. Bounded only by the Kubernetes API server CRD count and the EG IR builder's preceding limits.
**Recommendation:** Add count limits at the `EnvoyGateway` config level (max routes per gateway, max listeners per gateway) and emit a status condition when exceeded, instead of generating ever-larger xDS snapshots.

## Reviewed, no issues
- No recursion was found in IR processing. All structures are linear traversals.
- IR `Validate()` methods are linear and well-bounded.

---

## 5. Snapshot races / version monotonicity

## [LOW] Snapshot version derived from trace ID can collide; cache version counter resets to 0 at MaxInt64
**File:** /home/user/gateway/internal/xds/cache/snapshotcache.go:81-92, :127-138
**Description:** `GenerateNewSnapshot` chooses the snapshot `version` string as the **trace ID** if the span context is valid (`sc.TraceID().String()`), else the monotonic counter. Trace IDs are 128-bit random and collision risk is negligible in practice, but tracing-injected versions are not monotonic. If a buggy translator produced a non-trace-context (e.g., parent_ctx is replaced), the counter is used. The counter wraps to 0 at `MaxInt64` (line 131-133); after wrap, the same version string is reused, which Envoy will silently treat as "no change" and skip applying the snapshot. A long-lived control plane that hits ~9.2e18 updates would stop pushing changes — vanishingly unlikely in practice but a correctness bug.
**Recommendation:** Use a strict monotonic counter or a TraceID+counter combination. Refuse to reuse versions after wrap (or wrap to a sentinel that won't reuse).

## [LOW] Snapshot stays at last-known-good on translation error, with no operator-visible alert
**File:** /home/user/gateway/internal/xds/runner/runner.go:329-354
**Description:** The runner deliberately keeps Envoy on the previous snapshot if translation reports a system-level error (`if err == nil { ... GenerateNewSnapshot ... }`). The comment notes this is intentional. The risk is that an operator changes an IR resource expecting it to take effect, but a translation error (logged at `Error`) means it silently does not; this could hide a security-relevant misconfiguration (e.g., a removed allow-list never being removed). The status path for EnvoyPatchPolicy is updated, but for other CRD types there is no per-resource status signaling translation-skip.
**Recommendation:** Document this behavior and emit a metric/status condition when translation fails so operators can alert on it.

## Reviewed, no issues
- All snapshot map mutations are under `s.mu` (`snapshotcache.go`).
- `OnStreamRequest` properly returns early when no snapshot exists for the cluster yet (lines 234-238).
- `OnDelta...` paths mirror the SOTW paths and are mutex-guarded identically.

---

## Summary of severities

- HIGH (2): JWT pod-binding bypass on `Extra == nil` + `podName[0]` panic; default-mode cross-gateway impersonation via shared mTLS cert + attacker-chosen `node.Cluster`.
- MEDIUM (2): Bootstrap YAML template lacks per-value escaping for CRD-controlled OTel-sink strings; ResponseOverride / DirectResponse response headers bypass the HeaderValue regex used elsewhere.
- LOW (5): No gRPC `MaxConcurrentStreams`/`MaxRecvMsgSize` on xDS and global-ratelimit servers; ResponseOverride/DirectResponse body lacks an upper cap and Envoy's per-route max is auto-raised; translator loops over unbounded CRD-controlled slices; snapshot version monotonicity edge case; silent translation-skip on system error.
- INFO (4): xDS binds 0.0.0.0; non-crypto RNG in keepalive randomization; Lua/Wasm execute user code by design.
