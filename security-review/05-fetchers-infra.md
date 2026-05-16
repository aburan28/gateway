# Security Review: Fetchers & Infrastructure (Envoy Gateway)

Scope: `internal/wasm/`, `internal/infrastructure/`, `internal/utils/`, plus control-plane outbound HTTP triggered by CRDs (OIDC discovery, Wasm, JWKS, ext_authz/ext_proc).

---

## [HIGH] No SSRF protection on user-supplied Wasm HTTP URLs (control-plane fetch)
**File:** internal/wasm/httpfetcher.go:87-128, internal/wasm/cache.go:245-256, internal/gatewayapi/envoyextensionpolicy.go:1005
**Description:** When an `EnvoyExtensionPolicy` CR specifies `wasm.code.http.url`, Envoy Gateway (the control plane) directly fetches that URL with no SSRF mitigations:
- No host/IP validation. The URL hostname is resolved by Go's default resolver and dialed directly. Attackers with `EnvoyExtensionPolicy` create permission can point the URL at:
  - `http://169.254.169.254/...` (cloud IMDS — AWS, GCE, Azure metadata)
  - `http://127.0.0.1:<port>/...`, `localhost`, `[::1]` (in-cluster control-plane endpoints, kubelet `:10250`, `:10255`)
  - Internal RFC1918 / link-local CIDRs (other tenants in shared clusters)
  - Kubernetes API server (`https://kubernetes.default.svc`) using EG service account token if container can read it
- No DNS-rebinding protection. The URL is parsed once but Go re-resolves on dial, and a TTL=0 DNS record can return a public IP for parsing/validation and a private IP at dial time.
- No `CheckRedirect` configured. Default Go client follows up to 10 redirects, so even an external URL that 302s to `http://169.254.169.254/...` will be followed.
- Scheme allowlist is reasonable (`http`/`https` only at cache.go:245), but no host allowlist.

The same issue applies to `prepareFetch` for OCI URLs (cache.go:316-331); go-containerregistry's `remote.Get` will dial whatever host the user supplies and follow registry redirects, including to internal hosts via `Location` headers in registry blob fetches.

**Impact:** SSRF allowing the control plane to be used as a confused deputy: cloud IMDS credential theft, internal-service enumeration, blind probing of in-cluster services, and (when the response is large enough to be cached) returning attacker-controlled bytes that Envoy then loads as a Wasm filter.
**Recommendation:**
- Add a hostname/IP allowlist or denylist (block link-local 169.254.0.0/16, loopback, RFC1918 unless explicitly opted in by an admin allowlist).
- Resolve the hostname once, validate the resulting IP, and dial that IP via a custom `net.Dialer` `Control` callback so the resolved IP is checked at TCP-connect time (DNS-rebinding protection). Reuse the same approach the `tetragon`/`controller-runtime` SSRF guards use.
- Set `http.Client.CheckRedirect` to either disallow redirects to private addresses or cap at 0–1 redirects.
- Make the policy enforced at admission time (CEL validation on the URL), not just at runtime.

---

## [HIGH] No SSRF protection on OIDC issuer discovery URL
**File:** internal/gatewayapi/securitypolicy.go:1593-1648
**Description:** `discoverEndpointsFromIssuer` builds a request to `<issuer>/.well-known/openid-configuration` from `SecurityPolicy.spec.oidc.provider.issuer`. The control plane:
- Builds an `http.Client` with a 5s timeout (good) but no `CheckRedirect`, no IP/host validation, no DNS-rebinding protection.
- Decodes the response with `json.NewDecoder(resp.Body).Decode(&config)` (line 1631) with no body size limit — a malicious server can stream a multi-GB JSON document and OOM the control plane.
- The discovered `token_endpoint`, `authorization_endpoint`, and `end_session_endpoint` come straight from the response JSON. `validateTokenEndpoint` (line 1698) only blocks IPv4 literals as the hostname (and only IPv4 — IPv6 literals slip through), but does not check that they aren't loopback/link-local FQDNs (e.g. `localhost.example.com`, `instance-data.ec2.internal`, attacker-controlled CNAMEs to `169.254.169.254`). The `authorizationEndpoint` and `endSessionEndpoint` aren't validated at all.

The retry loop with `backoff.Retry` (line 1614) means each issuer URL gets multiple attempts, amplifying both SSRF probes and timing oracles.

**Impact:** A user with `SecurityPolicy` creation rights can:
1. Force EG to issue arbitrary GET requests to internal services (SSRF), including IMDS.
2. OOM the control plane via a giant JSON payload.
3. Cause subsequent OIDC redirects (which Envoy/the user agent handles) to point to internal-only endpoints exfiltrating session/code params.

**Recommendation:**
- Wrap the response body with `io.LimitReader(resp.Body, 1<<20)` (or smaller) before decoding.
- Add the same SSRF guards as the Wasm fetcher (host allowlist/denylist, DNS-rebinding-safe dial, redirect cap).
- Validate all three discovered endpoints against the same SSRF policy and against `https://` scheme.
- Fix `validateTokenEndpoint` (line 1705-1709) to also reject IPv6 literals and to reject hostnames that resolve to RFC1918/loopback/link-local.

---

## [HIGH] No SSRF protection on OIDC discovery body decode (decompression / size)
**File:** internal/gatewayapi/securitypolicy.go:1631
**Description:** `json.NewDecoder(resp.Body).Decode(&config)` with no `io.LimitReader` and no `Content-Length` check. Combined with no `Accept-Encoding` restriction (Go's default may transparently `gzip` decode), an attacker-controlled issuer can return a small gzip that decompresses into many GB.
**Impact:** Memory exhaustion / denial of service of the control plane via a small response body. The control plane is single-tenant for the cluster — DoS'ing it stops xDS updates for every gateway.
**Recommendation:** `body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))` then `json.Unmarshal(body, &config)`.

---

## [HIGH] Wasm HTTP fetcher uses `InsecureSkipVerify: true` for ALL "insecure" hosts
**File:** internal/wasm/httpfetcher.go:68-79, internal/wasm/cache.go:217
**Description:** The "insecureClient" disables TLS certificate verification entirely (`InsecureSkipVerify: true`). It is selected when `c.allowInsecure(u.Host)` returns true — which requires the host (or `*`) to be in `CacheOptions.InsecureRegistries`. Today `CacheOptions.InsecureRegistries` is never populated from any user/CRD-facing configuration (it is constructed from `defaultCacheOptions()` with an empty set in cache.go:138 and runner/runner.go:118). So in practice no host triggers the insecure client today.

However:
1. The plumbing exists and is one config-flag away from being exposed; once exposed, `InsecureRegistries: {"*"}` is documented as a wildcard meaning every host gets `InsecureSkipVerify: true` (options.go:51) — defeats TLS entirely for module fetches.
2. `tls.Config` does not set `MinVersion`, so even the "secure" client accepts TLS 1.0/1.1.
3. The `insecureClient` and its transport are reused across all fetches, so a single misconfiguration globally weakens TLS.

**Impact:** MITM of any Wasm module download → arbitrary code execution inside Envoy data plane (Wasm runs in the proxy). Combined with no cosign/signature verification (see below), the only integrity check is the operator-supplied SHA256 — which is optional.

**Recommendation:**
- Require the SHA256 field to be set whenever `InsecureRegistries` is enabled.
- Refuse to load wildcards in `InsecureRegistries`. Require an exact host[:port].
- Set `MinVersion: tls.VersionTLS12` (or 1.3) on every `tls.Config` constructed in `internal/wasm/`.

---

## [HIGH] No image / module signature verification (supply-chain)
**File:** internal/wasm/cache.go:286-308, internal/wasm/imagefetcher.go (whole file)
**Description:** The Wasm pipeline never verifies an OCI cosign signature, image attestation, or any digital signature. Trust is bootstrapped solely by:
- An optional, operator-supplied SHA256 in the EnvoyExtensionPolicy CR (`config.Code.HTTP.SHA256` / `config.Code.Image.SHA256`). If absent, *any* binary returned by the registry is accepted (cache.go:292 — "Update the checksum with the one from the downloaded binary.").
- A digest-style URL (`oci://repo@sha256:...`) is also honored (cache.go:177-184), but the user is allowed to use mutable tags or `:latest` (envoyextensionpolicy.go:1062 — auto-appends `:latest` if no tag/digest).

There is no cosign, no Notary, no transparency-log check. `extractDockerImage`/`extractOCIStandardImage`/`extractOCIArtifactImage` accept three different media types and silently fall through to the next on failure (imagefetcher.go:140-169) — a malicious registry can serve any of three formats.

**Impact:** Compromised/typosquat registry → arbitrary Wasm code in every Envoy proxy.
**Recommendation:**
- Require either a pinned digest in the URL or a SHA256 in the CR (reject when both absent).
- Optionally support cosign `verify` via `sigstore-go`; gate by an EnvoyGateway config option.
- When `:latest` is auto-appended, require a checksum.

---

## [HIGH] Decompression bomb: gzip read with no size limit
**File:** internal/wasm/httpfetcher.go:188-201 (`getFileFromGZ`), internal/wasm/imagefetcher.go:329-334 (`extractOCIArtifactImage`)
**Description:**
- `getFileFromGZ` calls `io.ReadAll(zr)` with no `LimitReader` around the *decompressed* stream. The compressed input is bounded to 256 MiB (`maxWasmSize`) but a 256 MiB gzip can decompress to many TB.
- `extractOCIArtifactImage` calls `io.ReadAll(r)` on `layer.Compressed()` with no limit at all — the layer size is whatever the registry says; a hostile registry can stream gigabytes.

**Impact:** Memory exhaustion / OOM-kill of the EG control plane pod by serving a compression bomb. Single-tenant control plane → cluster-wide outage.
**Recommendation:** Wrap the decompressed reader with `io.LimitReader(zr, maxWasmSize)` (and `io.LimitReader(r, maxWasmSize)` for the OCI artifact path). Treat exceeding the limit as a fetch error.

---

## [HIGH] Tar header `h.Size` used to allocate buffer (memory exhaustion)
**File:** internal/wasm/imagefetcher.go:274, internal/wasm/httpfetcher.go:176
**Description:** Both extraction paths do:
```go
ret := make([]byte, h.Size)
```
where `h.Size` is the `int64` size from the untrusted tar header. Even though the tar reader is wrapped in a 256MiB `LimitReader`, the `make` call happens *before* any read — so a tar header claiming `Size = 1<<60` will attempt to allocate 1 EB and panic / OOM the process. (The `io.ReadFull` would fail later, but the allocation already happened.)
**Impact:** A single malicious image/HTTP response causes EG control plane OOM crash.
**Recommendation:**
```go
if h.Size < 0 || h.Size > maxWasmSize {
    return nil, fmt.Errorf("tar header size %d exceeds limit", h.Size)
}
ret := make([]byte, h.Size)
```

---

## [MEDIUM] Data race on `HTTPServer.mappingPath2Cache`
**File:** internal/wasm/httpserver.go:148-157, 199-208
**Description:** `Get()` writes `s.mappingPath2Cache` under `s.Lock()` (line 169-208), but `ServeHTTP()` reads the same map (line 152) with no lock. Concurrent reads while `Get()` is mutating violate Go's map safety guarantee and can panic ("concurrent map read and write").
**Impact:** Crash of the Wasm-serving HTTP server, denying Envoy proxies access to their Wasm modules. With Go's `-race` builds, this is also a hard failure.
**Recommendation:** Use a `sync.RWMutex` and `RLock()` in `ServeHTTP`, or guard the map read with the existing `Lock()`. Alternatively, switch to `sync.Map`.

---

## [MEDIUM] Wasm HTTP server has no auth on cached-module endpoint
**File:** internal/wasm/httpserver.go:113-157, 199-216
**Description:** The HTTP server on `:18002` serves cached Wasm modules to any client that knows the URL path. Defense rests entirely on the `mappingPath = sha256(originalURL || salt)` "unguessable" path. Comments acknowledge the threat: "to prevent unauthorized users from accessing the Wasm module using EnvoyPatchPolicy" (line 62-65).

Issues:
1. The salt is the OIDC HMAC secret (runner/runner.go:111-113), shared cluster-wide. If any in-cluster pod can read that secret (it lives in the controller namespace), it can compute every mapping path.
2. There is no authentication check (no client cert verification beyond TLS handshake; no token check). When `TLSConfig` is nil, the server accepts plain HTTP.
3. `http.ServeFile(w, r, entry.localFile)` (line 153) — `entry.localFile` is set by EG itself so not user-controlled, but `ServeFile` honors `Range` requests and special handling of `..` in the request path; the use of `strings.TrimPrefix(r.URL.Path, "/")` and a map-key lookup avoids traversal here, but `http.ServeFile` itself will redirect on certain path cleanups, which can be surprising. (Not directly exploitable today.)
4. The "unguessable path" includes a `.wasm` suffix — knowing the URL pattern + salt is enough to enumerate.

**Impact:** Any in-cluster pod with the OIDC HMAC secret can download every Wasm module EG has ever cached, including those from private OCI registries with proprietary code.
**Recommendation:**
- Require mTLS for the wasm server and use SAN/DN validation against the Envoy proxies' service-account-issued certs.
- Or rotate to a per-policy random salt held only in memory.

---

## [MEDIUM] OCI registry auth: `Insecure` set but TLS minimum version not configured
**File:** internal/wasm/imagefetcher.go:80-88
**Description:** When `Insecure: true`, the image fetcher clones `remote.DefaultTransport` and sets `InsecureSkipVerify: true`. The cloned transport has no `MinVersion` set, so it can negotiate TLS 1.0 with the registry. Bearer-token auth (`Auth: cfg.Auth`) is then sent over that downgraded connection.
**Impact:** Registry credentials harvestable on networks where TLS 1.0 downgrade is feasible.
**Recommendation:** Always set `MinVersion: tls.VersionTLS12`, even when `InsecureSkipVerify: true`.

---

## [MEDIUM] EnvoyProxy `Patch` field allows users to escalate pod privileges
**File:** internal/utils/merge.go:18-64, internal/infrastructure/kubernetes/proxy/resource_provider.go:308, 449, 520, 607; api/v1alpha1/validation/envoyproxy_validate.go:102-115
**Description:** `EnvoyProxy.spec.provider.kubernetes.envoyDeployment.patch` (also for `envoyService`, `envoyDaemonSet`, `envoyHpa`, `envoyPDB`) is a strategic-merge / JSON-merge patch applied verbatim to the rendered Pod/Deployment/Service spec. The only validation is "patch must not be empty" and "patch type must be one of two known values" (envoyproxy_validate.go:105-112). No restriction on patch contents.

A user with permission to create `EnvoyProxy` (a namespaced CR) can therefore:
- Set `securityContext.privileged: true`, `runAsUser: 0`, drop `ReadOnlyRootFilesystem`, add `CAP_SYS_ADMIN`.
- Set `hostNetwork: true`, `hostPID: true`, `hostIPC: true`.
- Mount `hostPath: /` and exfiltrate node files via the proxy.
- Add additional containers (sidecars) with `image: attacker/curl` and run arbitrary code in the gateway-controller-managed namespace.
- Override the ServiceAccount on the pod (depending on patch fields), or set `automountServiceAccountToken: true` on a SA that has more rights.
- Patch the `image:` to a malicious registry.

This is a known design choice in EG ("escape hatch"), but it must be flagged: the security boundary is "anyone who can write `EnvoyProxy` CRs can compromise the Kubernetes node where the proxy runs." Many cluster operators may not realize `EnvoyProxy` write-access ≈ root on a node.

**Impact:** Privilege escalation from EnvoyProxy author → node-level code execution.
**Recommendation:**
- At minimum, document this in the threat model and security guide and recommend gating with PodSecurityAdmission / OPA / Kyverno policies on the resulting pod spec.
- Consider implementing a built-in admission-style validator on the patched object: reject patches that introduce `hostNetwork`, `hostPID`, `hostIPC`, `privileged`, `hostPath` volumes, raised capabilities, or that change `serviceAccountName`/`automountServiceAccountToken`.
- Optionally provide a `EnvoyGateway`-level config flag `disablePodPatchEscalations: true` that enforces the above.

---

## [MEDIUM] Default Envoy image pinned by mutable tag, not digest
**File:** internal/infrastructure/kubernetes/proxy/resource.go:516-552, internal/infrastructure/host/proxy_infra.go:183-199
**Description:** `resolveProxyImage` defaults to `egv1a1.DefaultEnvoyProxyImage` (a `name:tag` reference) and `getImageTag` parses out only the tag portion. When the user supplies `containerSpec.ImageRepository`, the code reuses the default tag — never a digest. Pulled images are not pinned by `@sha256:`, so registry compromise or a tag-overwrite attack at the registry mutates what every gateway pod runs on next pull.
**Impact:** Supply-chain risk: a poisoned registry tag silently rolls into every Envoy proxy.
**Recommendation:** Allow (and prefer) digest-pinned default images. Document the digest of each official Envoy build and use it by default.

---

## [MEDIUM] Wasm cache file path encodes only `name` hash, but checksum can be empty
**File:** internal/wasm/cache.go:162-171, 365-372
**Description:** `getModulePath` computes the file path as `<baseDir>/<sha256(name)>/<checksum>.wasm`. The `name` is `moduleNameFromURL(downloadURL)` (the OCI repo without tag, or the full HTTP URL). The `checksum` is `mkey.checksum`, which is taken from the user-provided checksum (or the OCI digest if present). If the user supplies a different checksum but the same URL, two distinct files are stored side-by-side in the same directory — that is fine. But the directory hash is over the *URL*, not the *content*. This means:
- Two different policies pointing at the same URL share the same cache directory.
- The first policy's module remains on disk and is served whenever the cached entry is hit by name only. The mux only invalidates by `cacheKey.moduleKey` (URL+checksum), so a cache poisoning attempt by a second tenant supplying the same `(URL, checksum)` pair is only safe if the `checksum` is treated as authoritative — which it is.

A subtler issue: `mkey.checksum` is derived from a **user-supplied** value before any fetch happens. If the user lies about the checksum, `getEntry` (line 453) returns the cached entry on a checksum-only match, even if the module on disk does not actually have that checksum (no recompute on cache hit). With multi-tenant `EnvoyExtensionPolicy` write access and a colliding URL, tenant A could front-run tenant B by pre-populating a `(URL, checksum)` pair that points at attacker-controlled content (the actual file IS what tenant A downloaded, but tenant B then trusts the on-disk file because the cache says checksum matches). Tenant B's stated checksum must match tenant A's, so this is a chosen-checksum attack.

**Impact:** Limited; requires colluding tenants and same-URL same-checksum. Still, the cache should re-verify the on-disk file's hash on rare access (or at least upon initial deserialization at startup, although there's no startup deserialization here — cache is in-memory).
**Recommendation:** When `getEntry` returns a hit, verify `entry.checksum == key.checksum` (it is the wasm-binary checksum, not the OCI image checksum) and, optionally, re-hash the file periodically.

---

## [LOW] Wasm cache directory created with `0o755`
**File:** internal/wasm/cache.go:167
**Description:** Per-module dirs under the cache root are created with `0o755` (world-readable). The cache root itself is created by `docker/pkg/fileutils.CreateIfNotExists(..., true)` (runner/runner.go:126) which uses `0o700`, so this is mitigated when the parent is locked down. But `0o755` on subdirectories is still inconsistent. The wasm files themselves are `0o600` (cache.go:370) — good.
**Impact:** Low. Inside an EG pod the only other process is the proxy sidecar, but it runs as a different user.
**Recommendation:** Use `0o700` for cache subdirectories.

---

## [LOW] `permissionCacheKey` is `hex.EncodeToString(image_url || pull_secret)`
**File:** internal/wasm/premissioncache.go:114-119
**Description:** The key is a hex-encoded concatenation of the URL and the docker-config-json bytes of the pull secret. The full pull secret (which contains base64'd registry credentials) is therefore retained in memory as a hex-encoded map key for the lifetime of the cache entry (24 h by default). This is also written to log lines via `e.image.String()` — though `image.String()` is just the URL, not the secret.

Bigger issue: the key is *not hashed*. Anyone with a memory dump (debugger, core dump, `delve`) recovers credentials in plaintext. A `sha256(url || secret)` digest would be sufficient as a key.
**Impact:** Exposure of registry credentials in process memory beyond the time the secret is actively used.
**Recommendation:** `key := hex.EncodeToString(sha256.Sum256(append([]byte(image.String()), pullSecret...))[:])`.

---

## [LOW] `validateTokenEndpoint` only blocks IPv4 literals
**File:** internal/gatewayapi/securitypolicy.go:1698-1718
**Description:** Only `ip.Unmap().Is4()` is rejected. IPv6 literals (`http://[::1]/...`, `http://[fd00::1]/...`) pass validation. Hostnames that resolve to private addresses also pass.
**Impact:** Mostly defense-in-depth — the OIDC token endpoint is read by Envoy, not by EG. But Envoy will then send tokens to an attacker-controlled internal address.
**Recommendation:** Reject all non-loopback-public IPs (v4 and v6); resolve and validate hostnames.

---

## [LOW] Wasm HTTP fetcher has no `Accept` / `Content-Type` validation
**File:** internal/wasm/httpfetcher.go:117-128
**Description:** The fetched body is validated only by magic-bytes check (`isValidWasmBinary`, cache.go:512-515) plus an attempt to "unbox" gzip/tar wrappers (`unboxIfPossible`). The HTTP `Content-Type` header is ignored. If the unboxing logic ever has a bug that returns non-Wasm bytes, the server would serve them blindly. (Today the magic-byte check after unboxing prevents this.)
**Impact:** Defense-in-depth.
**Recommendation:** Optionally enforce `application/wasm` or `application/octet-stream` Content-Type.

---

## [LOW] No upper bound on retry-induced load
**File:** internal/wasm/httpfetcher.go:99-150
**Description:** The fetcher retries up to `requestMaxRetry` times (default 5) for each `Get()`, with exponential backoff. Combined with no rate limiting on `EnvoyExtensionPolicy` reconciles, a tenant can create N policies pointing at the same slow internal URL and force EG to issue 5N parallel SSRF probes. Failed-attempt counter in `httpserver.go:171-192` only stops *future* requests after exceeding `MaxFailedAttempts` (default 10) — it does not bound the *current* in-flight request.
**Impact:** Amplified SSRF / amplified outbound load.
**Recommendation:** Add per-host rate limiting on outbound fetches.

---

## [INFO] Reviewed, no issues
- `internal/infrastructure/host/paths.go` — XDG paths pulled from CR with no path-traversal check, but only consumed by func-e in the same process; no cross-tenant impact.
- `internal/utils/merge.go` — JSON marshal/unmarshal cycle; not a security issue itself, but is the vehicle for the EnvoyProxy patch escalation flagged above.
- `internal/wasm/options.go` — sane defaults; only problem is the `*` wildcard for `InsecureRegistries` (covered above).
- `internal/infrastructure/kubernetes/proxy/resource_provider.go` ServiceAccount: `AutomountServiceAccountToken: ptr.To(false)` is correctly set on both the SA (line 170) and the Pod spec (line 418, 632) — good.
- `internal/infrastructure/kubernetes/resource/resource.go:113-129` — `DefaultSecurityContext` is hardened (drop ALL caps, no privilege escalation, RuntimeDefault seccomp). Good baseline.
- `internal/wasm/httpserver.go:113-124` — `ReadHeaderTimeout: 15s` is set (good — prevents slowloris on the wasm server itself).

---

# Summary
The Wasm fetch path is the highest-risk surface: SSRF + decompression bomb + tar-header allocation + no signature verification + cache-server with weak access control. The OIDC discovery flow is similarly exposed for SSRF. The infrastructure provisioner is solid by default but the `Patch` escape hatch is a powerful escalation primitive that should be documented and (ideally) gated.

Top fixes to ship:
1. SSRF guards (resolved-IP validation, redirect cap) in `internal/wasm/httpfetcher.go` and `internal/gatewayapi/securitypolicy.go:discoverEndpointsFromIssuer`.
2. Bounded reads in all decompression / tar-extraction paths in `internal/wasm/httpfetcher.go` and `internal/wasm/imagefetcher.go`.
3. Lock the read of `mappingPath2Cache` in `httpserver.ServeHTTP`.
4. Body-size limit on the OIDC discovery JSON decode.
5. Document EnvoyProxy `Patch` privilege escalation; consider deny-list for hostNetwork/hostPath/privileged.
