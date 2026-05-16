# Envoy Gateway Control Plane Security Review

Scope: admin server, extension gRPC client, kubernetes admission webhook, metrics endpoint, troubleshoot, filewatcher/config loader, CLI (egctl).

---

## Admin Server (`internal/admin/`)

## [LOW] Admin server console always exposes provider resource summary and (when enabled) pprof on a routable interface, with no authentication or auth-Z
**File:** `internal/admin/server.go:63-102`, `internal/admin/console/handlers.go:37-56`, `internal/admin/console/api.go:127-727`, `api/v1alpha1/envoygateway_helpers.go:283-298`, `api/v1alpha1/envoygateway_types.go:19-22`
**Description:** The admin server binds to `127.0.0.1:19000` by default (good), but the address (`Host`/`Port`) is fully user-configurable through `EnvoyGateway.Admin.Address`. Once a user/operator changes it to `0.0.0.0` (which the helm chart and CRD validation explicitly permit), there is **no authentication, no TLS, and no authorization** on:
  - `/api/server_info` — returns the entire `EnvoyGateway` config object (`h.cfg.EnvoyGateway`) — this includes the global rate-limit backend address, OIDC HMAC secret name, telemetry sink endpoints, gateway controller name, custom-resource configuration, etc.
  - `/api/config_dump?resource=...` — enumerates every Gateway-API and Envoy Gateway custom-resource (gateway/httproute/securitypolicy/etc.) in the cluster, including `BackendTLSPolicy`, `EnvoyExtensionPolicy`, OIDC `SecurityPolicy`, etc.
  - `/api/config_dump?resource=secret` — returns Kubernetes `Secret` objects with `data` redacted to `[redacted]`, but **annotations on the Secret** and the secret **name + namespace + type** are preserved. Annotations can themselves contain sensitive metadata (e.g. cert-manager often attaches `cert-manager.io/...` and SOPS often attaches DEK fingerprints; some users put debug data in annotations). Note `redactSecrets` *does* strip ManagedFields and Annotations (see `console/api.go:298-299`), so this is mostly OK — but only the dedicated `case "secret"` and `case "all"` paths call `redactSecretData`. In `loadConfigDump()` the secret name + namespace are listed at `console/api.go:617-624` (no data leak).
  - `/api/metrics` — full controller-runtime Prometheus metrics. These metrics include the per-pod stream identifiers (see metrics finding below), runtime Go memory stats, etc. — useful to an attacker fingerprinting EG.
  - `pprof` (when `EnablePprof=true`) at `/debug/pprof/*` — full goroutine, heap, allocs, profile, trace, cmdline, symbol; pprof leaks process memory and command line.
**Impact:** If the operator changes `Admin.Address.Host` to `0.0.0.0` (or to the pod IP for cluster-wide access, e.g. when running off-Kubernetes for inspection), all of the above is reachable without authentication. The console also actively exports the full live `EnvoyGateway` config which contains the full Extension Manager configuration (the gRPC server hostname/port the EG control plane will call, retry/MaxMessageSize), telemetry sink addresses, JWT Provider issuer URLs, controller name. This is information disclosure useful to an attacker; pprof additionally enables remote heap dumping (which can disclose arbitrary in-memory data including secret material that has flowed through the control plane).
**Recommendation:**
  1. Refuse to bind to non-loopback addresses unless an operator explicitly opts in with an `--admin-listen-allow-non-loopback` flag, or, alternatively, require a token / mTLS client cert when the bind address is non-loopback.
  2. For pprof, ALWAYS require an auth token even on loopback (`pprof` on loopback is exploitable via the OS browser or any code that can `curl` from the pod, including malicious sidecars).
  3. Validate `EnvoyGatewayAdminAddress.Host` to forbid `0.0.0.0` / `::` unless a `EnableExternalAccess: true` field is set.
  4. Document explicitly that the admin endpoint MUST NOT be exposed externally (the docs in `EnvoyGatewayAdmin` types do not mention this risk).

## [INFO] Admin server config-dump response leaks structured info about all controller-watched resources
**File:** `internal/admin/console/api.go:202-277`, `internal/admin/console/api.go:434-712`
**Description:** When `EnvoyGateway.Provider.Kubernetes.Watch` is set to a list of namespaces, the admin `/api/config_dump` call enumerates only resources from the watched namespaces (because they pass through the controller's resource cache). However, if EG is run with cluster-wide watch (default), this endpoint exposes the **name and namespace of every Gateway, Route, Policy, Service, Secret, ConfigMap, EndpointSlice and Backend across the cluster** — it is essentially `kubectl get all -A` filtered to types the controller watches. Combined with the LOW finding above (no auth on the admin server when bound non-loopback), this is a privilege-escalation risk.
**Recommendation:** Same as above — gate on auth.

## [INFO] Admin server `EnableDumpConfig=true` writes the entire `EnvoyGateway` config (including secret names) to stdout via `spew.Dump`
**File:** `internal/admin/server.go:41-45`
**Description:** When set, `spew.Dump` of `r.cfg` is written to the controller's stdout, which goes to pod logs. Pod logs are typically world-readable to anyone with `pods/log` RBAC. The dumped config includes JWT issuer URLs, OIDC client IDs (not secrets — but client ID + issuer is meaningful), telemetry endpoints, extension server addresses, etc.
**Recommendation:** Document that this should only be enabled for short-lived debugging.

---

## Extension gRPC Manager (`internal/extension/`)

## [HIGH] Outbound extension gRPC connection defaults to plaintext (`insecure.NewCredentials()`); no per-CR validation that TLS is configured for production
**File:** `internal/extension/registry/extension_manager.go:299-322`, `api/v1alpha1/envoygateway_types.go:799-803`
**Description:** When `EnvoyGateway.ExtensionManager.Service.TLS` is nil, the gRPC dial is constructed with `insecure.NewCredentials()` (line 321). The TLS struct is `+optional` in the CRD with no default, so a misconfiguration silently downgrades to plaintext. Because the extension server is the trusted plugin that mutates xDS (see HIGH finding below), any MITM on the cluster network could:
  1. Read the inbound xDS resources EG sends to the extension (which include cluster lists, listener configs, TLS Secrets, route configs — i.e. the entire xDS table).
  2. Modify the extension's response and inject arbitrary xDS that EG will install.
**Recommendation:** Make TLS mandatory by default (e.g. require `TLS` to be non-nil OR require an explicit `AllowPlaintext: true` field). At minimum, log a high-severity warning at startup when an extension is configured without TLS. Validate at admission time that the `Service.TLS.CertificateRef` is present unless explicitly opted out.

## [HIGH] Extension manager treats the extension's xDS response as fully trusted and merges it into the live xDS (privilege escalation by design — should be documented)
**File:** `internal/extension/registry/xds_hook.go:48-161`, `internal/xds/translator/translator.go:163-180,209-247`
**Description:** All five extension hooks (`PostRouteModifyHook`, `PostClusterModifyHook`, `PostVirtualHostModifyHook`, `PostHTTPListenerModifyHook`, `PostTranslateModifyHook`) take whatever the extension server returns and assign it directly back into the xDS config. There is no:
  - schema validation of returned protos beyond the final `tCtx.ValidateAll()` at `translator.go:177` (which only checks well-formedness, not policy).
  - bound on what fields the extension can set (e.g. extension can set arbitrary cluster transport sockets including disabling TLS on backend connections, replacing endpoint addresses, adding `lua` or `wasm` filters that execute arbitrary code, replacing route prefix matchers with `*`, exfiltrating via custom access-log providers, swapping `Secret` resources with attacker-supplied PEM, etc.).
  - access control — the extension can change xDS for any Gateway, not just the resources its `Group/Kind` was registered for.
**Impact:** A compromised or malicious extension server has FULL control over what Envoy data planes do across the cluster — e.g. it can route bank.example.com traffic to attacker.com, it can disable TLS verification on backend connections, it can install `lua` filters that exfiltrate request bodies. This is essentially a built-in admin-level backdoor.
**Recommendation:** This is a documented "trust the extension" model. Strongly improve documentation to make the trust boundary explicit ("an extension server has the same authority as Envoy Gateway itself"). Consider adding: (1) a list of allowed mutations (e.g. only allow setting filter chain, not transport_socket), (2) per-Gateway authorization scope so an extension can only modify its registered resources' xDS.

## [HIGH] Extension RPCs use `context.Background()` with no timeout — a hung extension server stalls the xDS pipeline indefinitely
**File:** `internal/extension/registry/xds_hook.go:55-57,79-81,96-98,116-118,144-146`
**Description:** Every extension hook RPC uses `ctx := context.Background()` and passes that to the gRPC client. There is no `context.WithTimeout`, no per-call deadline, and the gRPC service config built in `buildServiceConfig()` (extension_manager.go:484-525) only sets retry policy — not a per-attempt timeout. If the extension server hangs (e.g. blocks on a database call that times out at the OS TCP keepalive horizon, ~2 hours), the xDS translation goroutine for that proxy is blocked. Since the translation runs in the xDS subscription handler, this stalls config updates for ALL gateways, not just the one being processed.
**Impact:** Single misbehaving / overloaded / malicious extension server can freeze the entire Envoy Gateway control plane.
**Recommendation:** Add `context.WithTimeout(ctx, ...)` for each hook call. Make the timeout configurable on `ExtensionService` (default ~5s).

## [MEDIUM] Extension RPC `MaxMessageSize` defaults to gRPC built-in (4 MB) but is uncapped on the upper end
**File:** `internal/extension/registry/extension_manager.go:335-345`, `api/v1alpha1/envoygateway_types.go:703-710`
**Description:** When `MaxMessageSize` is unset, gRPC defaults to ~4 MB recv. When set, the validator only checks `1 ≤ value ≤ math.MaxInt`. An operator (or an adversarial admin) could set 16 GB; combined with the lack of timeout, a single oversized response would exhaust EG memory.
**Recommendation:** Cap `MaxMessageSize` validation at a reasonable bound (e.g. 256 MB).

## [MEDIUM] When extension is configured without `FailOpen`, an extension RPC error fails the entire xDS translation and the previous xDS state is preserved indefinitely
**File:** `internal/extension/registry/extension_manager.go:134-137`, `internal/xds/translator/translator.go:165-173,236-245`
**Description:** With `FailOpen=false` (the default), if the extension server returns ANY error during translation, EG aborts and emits no xDS update. Combined with no timeout, a flaky extension can wedge the gateways at the last good config — meaning new HTTPRoutes/SecurityPolicies/etc. will never apply. This is a denial-of-service availability concern, not a confidentiality one.
**Recommendation:** Document the trade-off; consider adding a per-hook fail-open setting and a metric/alert for extension RPC failure rate.

## [LOW] Extension manager `getExtensionServerAddress` accepts `Service.IP` and `Service.FQDN` from the EnvoyGateway config; no validation that the IP is in a private range
**File:** `internal/extension/registry/extension_manager.go:168-181`
**Description:** The extension server address is simply `net.JoinHostPort` of whatever the operator configured. While the `EnvoyGateway` config itself is operator-controlled (so this is not directly attacker-controlled), if an attacker can influence the EnvoyGateway config (e.g. via a misconfigured GitOps repo PR), they can point the extension server to any IP — including a metadata endpoint (169.254.169.254), private RFC1918, or external attacker host. Combined with the plaintext default (HIGH above), this is exfiltration.
**Recommendation:** Optional — log a warning when the extension server resolves to a link-local or metadata range.

## [INFO] In-memory extension manager (`NewInMemoryManager`) overrides credentials with `insecure.NewCredentials()` regardless of TLS config
**File:** `internal/extension/registry/extension_manager.go:90-132`
**Description:** This is correct behavior for the in-memory manager (used in unit tests / programmatic embedding) since the connection never leaves the process, but worth noting that when called with a `cfg.Service` that has TLS configured, the TLS opts are *appended* but the `insecure.NewCredentials()` is also there — gRPC will use the last `WithTransportCredentials` option set, and the order in the code (insecure first, then TLS opts appended) means TLS wins. Verify this with tests; the in-memory manager wouldn't actually negotiate TLS over a bufconn anyway.
**Recommendation:** No action; flagging for awareness.

---

## Admission Webhook (`internal/provider/kubernetes/topology_injector.go`, `internal/provider/kubernetes/kubernetes.go:204-226`)

## [LOW] Admission webhook (proxy-topology-injector) is correctly mTLS-protected, `failurePolicy=Ignore`, and `sideEffects=None` — minor concerns
**File:** `internal/provider/kubernetes/kubernetes.go:57-67,204-226`, `charts/gateway-helm/templates/envoy-proxy-topology-injector-webhook.yaml:30-62`, `internal/provider/kubernetes/topology_injector.go:30-104`, `internal/cmd/certgen.go:139-170`
**Description:** The webhook only handles CREATE on `pods/binding`, has `failurePolicy=Ignore` (good — a webhook outage cannot deny pod scheduling), `sideEffects=None`, restricts namespaceSelector to the EG release namespace (or watched namespaces), and rejects non-Envoy pods early. TLS server cert is generated by the certgen job and the `caBundle` is patched via the certgen RBAC (limited to `update`/`patch` on a single `MutatingWebhookConfiguration` by name). This is solid.
**Issues found:**
  1. The handler uses `m.Decoder.Decode(req, binding)` which decodes the raw object; if the AdmissionReview body is large (Kubernetes default 3MB request limit applies), it would consume memory but is bounded by the apiserver. No EG-specific body-size limit is set on the webhook server.
  2. The webhook reads the Pod (via `m.Get(ctx, podName, pod)`) and the Node (`m.Get(ctx, nodeName, node)`) without a per-request context timeout. If the API server is slow, this could pile up admission requests; failurePolicy=Ignore means failed admissions just skip injection.
  3. There's no rate limiting on admission webhook requests on the EG side.
  4. Cert rotation: certs are generated by a one-shot certgen `Job`, not continuously rotated. When the cert expires (one year per `crypto.GenerateCerts`), the webhook breaks until certgen is re-run. failurePolicy=Ignore makes this mostly a soft failure.
**Recommendation:** Set `MaxHeaderBytes` on the webhook server, add a context timeout to Get calls, schedule cert rotation reminders.

## [INFO] No validating webhook is registered (only the mutating topology injector)
**File:** `internal/provider/kubernetes/kubernetes.go:218`
**Description:** EG validates EnvoyGateway CRs via the CRD's OpenAPI schema and the in-controller `validation.ValidateEnvoyGateway` for the bootstrap config; there is no validating admission webhook for EG-specific CRs. This means malformed CRs are caught at translation time instead of admission time. This is the documented design; no action.

---

## Kubernetes Controller / RBAC (`charts/gateway-helm/templates/_rbac.tpl`)

## [MEDIUM] Default RBAC grants `secrets` read across the cluster (or across watched namespaces)
**File:** `charts/gateway-helm/templates/_rbac.tpl:31-42`, `charts/gateway-helm/templates/envoy-gateway-rbac.yaml:38-82`
**Description:** The `eg.rbac.namespaced.basic` rule grants `get/list/watch` on `configmaps`, `secrets`, `services`. When `Watch.Namespaces` is unset (the default), this is granted as a `ClusterRole`/`ClusterRoleBinding` — meaning the EG ServiceAccount can read every Secret in the cluster. This is the expected design (EG must read TLS secrets, JWT secrets, OIDC client secrets, BasicAuth user lists, API key secrets), but it makes the EG pod a high-value target. Compromise of the EG pod => read every Secret in the cluster.
**Recommendation:**
  1. Document the cluster-wide secrets risk prominently.
  2. Strongly recommend `NamespaceMode` / `Watch.Namespaces` deployments in production, where the rules are downgraded to `Role`/`RoleBinding` per namespace (which the helm chart does correctly — see `envoy-gateway-rbac.yaml:13-37`).
  3. Consider adopting a `ResourceNames`-restricted RBAC for secrets (only allow secrets referenced by Gateway/SecurityPolicy/etc.). This would require a different reconciliation pattern.

## [MEDIUM] Cluster-scoped RBAC includes `get/list/watch` of `nodes`
**File:** `charts/gateway-helm/templates/_rbac.tpl:158-168`
**Description:** EG needs node info for the topology injector. Node objects can leak cloud-provider-injected annotations including IAM role ARNs, internal IPs, sometimes credentials in user-supplied annotations. This is unavoidable for the topology injector but worth noting.
**Recommendation:** Document; consider gating node read on `topologyInjector.enabled`.

## [LOW] `ValidateSecretObjectReference` for extension/rate-limit TLS doesn't enforce ReferenceGrant
**File:** `internal/kubernetes/secret.go:21-42`, called from `internal/extension/registry/extension_manager.go:382,415` and `internal/infrastructure/kubernetes/ratelimit/resource.go:470`
**Description:** When `ext.Service.TLS.CertificateRef.Namespace` differs from EG's controller namespace, `ValidateSecretObjectReference` simply does `client.Get(ctx, key, secret)` against the requested namespace — it does NOT consult any `ReferenceGrant`. For Gateway-API CR cross-namespace refs, EG correctly checks ReferenceGrants in `internal/gatewayapi/validate.go:155,425,804-870,967,1085`. For the `ExtensionManager` config (which is in EnvoyGateway, an operator-supplied config) the lack of ReferenceGrant check is arguably fine because it is an operator-trusted config — however, if the operator has the EnvoyGateway config sourced from a less-trusted location (e.g. a multi-tenant GitOps), a malicious entry could reference and load an attacker-controlled secret from any namespace.
**Recommendation:** Document that `ExtensionManager.Service.TLS.CertificateRef.Namespace` is operator-trusted. If the multi-tenant case matters, add an allowlist.

## [INFO] Secret reconciliation processes OIDC `clientSecret`, OIDC `clientID` (when ref'd), API-key auth `CredentialRefs`, BasicAuth user lists, WASM image pull secrets — all in the controller's secret watcher
**File:** `internal/provider/kubernetes/controller.go:888,906,940,962,1244-1288,3059`
**Description:** The controller reads these secrets in plain memory and translates them into xDS. They flow through the in-process channels and the xDS snapshot. They are visible to the admin server (where they are properly redacted; see admin findings). They are also visible to any Goroutine that has access to the IR (extension hooks!).
**Recommendation:** No action; covered by extension trust finding.

---

## Metrics endpoint (`internal/metrics/`)

## [MEDIUM] Metrics endpoint binds to `0.0.0.0:19001` by default with no authentication
**File:** `api/v1alpha1/envoygateway_types.go:23-26`, `internal/metrics/register.go:79-105,109`
**Description:** `GatewayMetricsHost = "0.0.0.0"`, `GatewayMetricsPort = 19001`. The metrics endpoint exposes controller-runtime's full Prometheus registry plus the EG-defined metrics. There is no auth and no TLS. Anyone who can route to the EG pod can scrape its metrics.
**Impact:** Controller-runtime metrics include internal queue depth, work duration, and may expose timing oracles. The xDS metrics include node IDs (Envoy pod identifiers), per-stream IDs (see cardinality finding), and snapshot create/update counters. These are not directly secret but enable fingerprinting and reconnaissance.
**Recommendation:** Default to `127.0.0.1` (or document the pod-network exposure assumption). Optionally support TLS / bearer-token auth on `/metrics` for hardened deployments.

## [HIGH] xDS stream metric uses unbounded `streamID` label — cardinality explosion DoS
**File:** `internal/xds/cache/metrics.go:21-29`, `internal/xds/cache/snapshotcache.go:189-193,307`
**Description:** `xdsStreamDurationSeconds` is a `Histogram` with labels `streamID`, `nodeID`, `isDeltaStream`. `streamID` is a monotonically incrementing int64 produced by go-control-plane, with a NEW value per stream connection. Every Envoy reconnect (which happens on every config push that triggers stream rotation, on every Envoy pod restart, on network blips) creates a new `streamID`. The histogram series is recorded once on `OnStreamClosed`. Even if the metric is recorded only on close, the *Prometheus client library* keeps an entry for every label combination forever (the histogram is not a `SummaryVec` with auto-cleanup) until the process restarts.
**Impact:**
  1. Memory growth: each label combination instantiates an internal histogram with ~6 buckets — bounded ~hundreds of bytes per series. With thousands of Envoy pods and frequent restarts (e.g. K8s rolling deploy of 100 pods every 5min), label cardinality grows roughly linearly with stream count, eventually consuming significant memory in the EG control plane.
  2. Prometheus scrape blowup: thousands of series per scrape will overwhelm the Prometheus server too.
**Recommendation:** Drop the `streamID` label entirely (it provides no aggregation value); aggregate by `nodeID` and `isDeltaStream` only. If per-stream introspection is needed, expose it via the admin server, not as a Prometheus label.

## [INFO] Other metric labels are bounded
**File:** `internal/provider/kubernetes/metrics.go`, `internal/infrastructure/kubernetes/metrics.go`, `internal/message/metrics.go`, `internal/wasm/metrics.go`
**Description:** Other metric labels (kind, name/namespace where present, runner, message, hit) are bounded by code (kind ∈ a closed set), or namespace/name on infra-resource metrics — the latter is bounded by the number of EnvoyProxy/Gateway resources, which an operator controls. Acceptable.

---

## Troubleshoot (`internal/troubleshoot/`)

## [HIGH] Troubleshoot bundle collects ConfigMaps from the namespace verbatim — values are NOT redacted
**File:** `internal/troubleshoot/collect/troubleshoot_helper.go:582-621`, `internal/troubleshoot/collect/envoy_gateway_resource.go:96-100`
**Description:** `EnvoyGatewayResource.Collect` calls `configMaps(ctx, client, namespaceNames)` which fetches every ConfigMap in the namespace and serializes the entire object (including `data`) to YAML. ConfigMaps in the EG namespace include:
  - The Envoy bootstrap ConfigMap (which by default contains the static control-plane address and the inline xDS sotw config — generally not secret),
  - Any user-defined ConfigMap referenced by `EnvoyProxy.Spec.Bootstrap` or `EnvoyExtensionPolicy.WASM.code.ConfigMapRef`,
  - User-installed ConfigMaps not associated with EG at all.
ConfigMaps frequently contain certs (PEM CA bundles), HMAC keys (especially for OIDC), API tokens (operators sometimes put these in CMs by mistake), and other sensitive data.
**Recommendation:**
  1. At minimum, redact the `data` of any ConfigMap not owned by EG (filter by `app.kubernetes.io/managed-by=envoy-gateway` label).
  2. Better: collect only the specific ConfigMaps that EG generates (envoy-bootstrap CM and EG-config CM) by name.
  3. Secrets are NOT directly collected (good).

## [MEDIUM] Troubleshoot CustomResource collector dumps any CR in `gateway.envoyproxy.io` and `gateway.networking.k8s.io` groups including SecurityPolicies/EnvoyExtensionPolicies that may contain secret references and inline OIDC config
**File:** `internal/troubleshoot/collect/custom_resource.go:54-94`, `internal/troubleshoot/collect/troubleshoot_helper.go:91-223`
**Description:** All CRs in those groups are dumped to the bundle as YAML. This includes:
  - `SecurityPolicy` with OIDC issuer URLs, JWT provider URLs, OIDC `clientSecret` *secret reference* (name only, not value), API key field paths, BasicAuth user list secret refs.
  - `EnvoyExtensionPolicy` with Wasm image URLs, pull secret refs.
  - `EnvoyPatchPolicy` — inline JSON Patch payloads, which can contain anything an operator put there (including credentials!).
**Impact:** EnvoyPatchPolicy values in the bundle may reveal arbitrary inline secrets. Issuer URLs reveal which auth providers are in use.
**Recommendation:** Document the bundle's sensitivity. Optionally provide a redaction allowlist for the EnvoyPatchPolicy spec.

## [MEDIUM] Troubleshoot config-dump opt-in flag `enableSDS` defaults to false (good), but the trim logic only removes the `SecretsConfigDump` section — TLS Secret material may still appear in `ListenersConfigDump` inline filter chains
**File:** `internal/troubleshoot/collect/config_dump.go:139-161`
**Description:** `trimSDS` removes `type.googleapis.com/envoy.admin.v3.SecretsConfigDump` from `dump.Configs`. However, Envoy's listener config dump can include inline TLS context with PEM-encoded secrets in the `transport_socket.typed_config.common_tls_context.tls_certificates` field if SDS isn't used (rare in EG, since EG always uses SDS — so this is mostly theoretical). It also doesn't redact filter-chain typed configs that may include credentials (e.g. `wasm` env, `lua` source code with embedded keys, JWT inline keys).
**Recommendation:** Consider walking all config sections and redacting any field named `private_key`, `inline_string`, `inline_bytes` within `tls_certificate` or `secret`-typed messages. Today, relying on EG always using SDS is fragile.

## [LOW] Troubleshoot port-forwards to pod port 19000 (Envoy admin) and pod port 9090 (Prometheus) over an unauthenticated `http://localhost` connection; OK but no TLS validation
**File:** `internal/troubleshoot/collect/config_dump.go:127-133`, `internal/troubleshoot/collect/prometheus_metrics.go:91-101,143-173`, `internal/kubernetes/port_forwarder.go`
**Description:** Standard kubectl-style port-forward via SPDY/WebSocket. The forwarded local port is bound to localhost only, and the request is HTTP (no TLS). Anyone with local user privileges on the egctl host can race-connect to the local port and request `/config_dump` for the duration of the port-forward. In practice the port lives only for a single request. Acceptable.
**Recommendation:** None.

---

## File Watcher / Config Loader (`internal/filewatcher/`, `internal/envoygateway/config/loader/`)

## [LOW] Config-reload race: file content is hashed before delivering the event, but the subsequent `Decode` reads the file again — TOCTOU window
**File:** `internal/filewatcher/worker.go:87-141,242-263`, `internal/envoygateway/config/loader/configloader.go:67-100`, `internal/envoygateway/config/decoder.go:28-35`
**Description:** The fileWatcher hashes the file (`getHashSum`) when an fsnotify event fires; if changed, it forwards the event. The configloader then calls `config.Decode(r.cfgPath)` which `os.ReadFile`s the path again. There is a TOCTOU window between the hash computation and the second read — an attacker who can write to the config file (or the directory containing it) could substitute a different file between the hash check and the actual load. In Kubernetes ConfigMap-mounted scenarios, the file is replaced via symlink swap (the canonical k8s pattern; the test at `filewatcher_test.go:115-151` covers this). Symlink swaps are atomic via rename, so the worst case is that the previous version is loaded once. The `Decode` does call `validation.ValidateEnvoyGateway` which limits damage to acceptable schema; an attacker who can write the file can put any valid config there anyway.
**Recommendation:** Acceptable; document. To eliminate TOCTOU, pass the file contents through the event rather than re-reading.

## [LOW] FileWatcher follows symlinks via `os.Lstat`+`os.Open` semantics — directory the file lives in must be trusted
**File:** `internal/filewatcher/filewatcher.go:178-186`, `internal/filewatcher/worker.go:243`
**Description:** `getPath` uses `filepath.Clean` and `os.Lstat`; the parent directory is added to fsnotify. `os.Open` of the watched file follows symlinks. If an attacker can replace the symlink target (e.g. via a shared writable directory), they can cause EG to read an arbitrary file. Standard Linux file permissions apply; the EG container's filesystem is usually read-only or operator-controlled.
**Recommendation:** Document that the config directory must be writable only by trusted principals.

## [INFO] No size limit on the config file read by `os.ReadFile`
**File:** `internal/envoygateway/config/decoder.go:29`
**Description:** `os.ReadFile(cfgPath)` reads the entire file into memory. A malicious operator-side actor could provide a 100 GB config file to OOM the EG process at startup. This is operator-trusted input; no real risk.
**Recommendation:** Optional: cap at e.g. 10 MB.

---

## CLI (`cmd/egctl/`, `internal/cmd/egctl/`)

## [LOW] `egctl experimental dashboard envoy-proxy` invokes `xdg-open`/`open`/`rundll32` with the local-forwarded URL
**File:** `internal/cmd/egctl/dashboard_envoy.go:119-138`
**Description:** `exec.Command(...)` is used (not `sh -c`), so there is no shell injection. The URL passed is `fmt.Sprintf(urlFormat, fw.Address())` where `urlFormat="http://%s"` and `fw.Address()` is `localhost:<localPort>` from `netutil.LocalAvailablePort()` (a random open port). No external user-supplied data flows into `exec.Command` arguments.
**Recommendation:** No action.

## [LOW] `egctl translate` reads input file via `os.ReadFile(inFile)` — no size limit, no symlink restriction
**File:** `internal/cmd/egctl/translate.go:189-204`
**Description:** Standard CLI behavior — operator chooses the file. Acceptable.

## [INFO] egctl uses standard `clientcmd` flags via `genericclioptions.ConfigFlags` (kube-style) — kubeconfig handling delegates to client-go
**File:** `internal/cmd/egctl/config.go:197-205`, `internal/kubernetes/client.go:54-86`
**Description:** Uses `--kubeconfig` (or `KUBECONFIG` env). The kubeconfig file is read with the user's privileges. No special handling; relies on standard k8s tooling. No issues.

---

## Cross-cutting observations

## [INFO] Health probe server binds `:8081` (all interfaces) with no auth — exposes `/healthz` and `/readyz`
**File:** `internal/provider/file/file.go:227-262`, `internal/provider/kubernetes/kubernetes.go:55`
**Description:** Health probes don't expose sensitive data (just liveness/readiness state), but they DO confirm the EG pod is running. Standard Kubernetes pattern; acceptable.

## [INFO] xDS gRPC server (`internal/xds/runner/runner.go:181-211`) uses TLS + (in GatewayNamespaceMode) a JWT auth interceptor — well-designed for the in-scope review's adjacent control surface
**File:** `internal/xds/runner/runner.go:170-258`
**Description:** Out-of-scope but worth noting that the xDS server (which Envoy connects to) uses `credentials.NewTLS` and adds a `kubejwt.NewJWTAuthInterceptor` in GatewayNamespaceMode. Good.

## Reviewed, no issues
- `internal/admin/console/static/` — static asset serving, properly scoped via `http.StripPrefix("/static/")`
- `internal/extension/registry/extension_manager.go` certificate loading from secrets — uses controller-runtime client.Get with the ref'd namespace, validates cert/key parse errors
- `cmd/envoy-gateway/main.go` and `cmd/egctl/main.go` — trivial entry points
