# Topaz Security Review

**Target:** [aserto-dev/topaz](https://github.com/aserto-dev/topaz) @ commit `1189dc6` (`runtime-v1.16.2`)
**Date:** 2026-05-16
**Scope:** Static review of the Go source tree (295 files), shipped config templates, Dockerfile, and `go.mod`. No dynamic testing.
**Method:** Four parallel reviews — auth/authz, TLS/crypto/network, input validation/injection, secrets/config/dependencies.

All findings cite `file:line` against the cloned repo and have been de-duplicated where reviewers overlapped.

---

## Executive summary

Topaz is an authorization service; the security of its own auth surface is unusually important because compromise of the authorizer compromises every downstream PEP that trusts its decisions.

The most serious issues cluster around four themes:

1. **The default posture is fail-open.** A config that omits API keys silently turns into an anonymous service; a console gateway endpoint leaks the configured API key without auth.
2. **JWT identities are accepted without issuer pinning**, enabling identity spoofing and SSRF against arbitrary URLs.
3. **Credentials are exposed by side-channels** — timing leaks in API-key comparison and logging of the raw `Authorization` header at trace level.
4. **CLI / install flows default to TLS-insecure mode**, and the shipped schema config contains plausible-looking API keys that look real enough to be re-used by careless operators.

**Severity counts (de-duplicated):** 4 Critical / High-Critical, 9 High, 7 Medium, 4 Low, plus informational items.

---

## Critical

### C1. `/api/v1/authorizers` returns the configured API key with no authentication

**Files:** `topazd/app/topaz.go:205`, `topazd/app/handlers/authorizer.go:8-27`, `topazd/app/console.go:85-91`

The console gateway registers `/api/v1/authorizers` via `Mux.HandleFunc(...)` with no auth-middleware wrapper (compare `/api/v2/config` on `topaz.go:204`, which *is* wrapped). The handler unconditionally returns:

```go
APIKey: confServices.AuthorizerAPIKey
```

An anonymous caller that can reach the console gateway port (default `0.0.0.0:8080`) can `GET /api/v1/authorizers` and walk away with a live key for the authorizer service. Combined with C2 below, this becomes pre-auth full takeover of the policy decision point.

**Fix:** Wrap with the API-key middleware, gate the response on an authenticated user in context, and ideally never echo the bearer credential back from a config endpoint at all.

### C2. Service silently turns anonymous when no API keys are configured

**Files:** `pkg/config/topaz_config.go:105-109`, `topazd/app/middlewares/middlewares.go:19-26`, `pkg/config/templates.go:128-135`

```go
if len(c.Auth.APIKeys) > 0 {
    c.Auth.Options.Default.EnableAPIKey = true
} else {
    c.Auth.Options.Default.EnableAnonymous = true
}
```

Validation does not fail — it flips the service to anonymous. The middleware list elides the auth middleware entirely when `len(cfg.Auth.APIKeys) == 0`. An operator who removes/forgets keys ships a fully open authorizer. The schema template explicitly sets `enable_api_key: false`, `enable_anonymous: true`.

**Fix:** Default-closed. Refuse to start when no keys (and no JWT issuer / mTLS) are configured unless an explicit `--allow-anonymous` flag is set. Log loudly on every startup that hits this branch.

### C3. Hardcoded sample API keys shipped in the schema

**File:** `pkg/config/schema/config.yaml:43-45`

```yaml
keys:
  - "69ba614c64ed4be69485de73d062a00b"
  - "##Ve@rySecret123!!"
```

These look exactly like real credentials. Anyone copying the schema as a starting config inherits them. They are searchable, so Shodan-style scans for Topaz instances using either string are trivial. They are NOT in `.gitleaksignore`, which means either gitleaks isn't running in CI or it was waved through manually — either way, an audit gap.

**Fix:** Replace with `keys: []` plus a comment instructing the operator to generate a random key (`openssl rand -hex 32`). Emit a runtime warning if these literal values are present.

### C4. JWT issuer is unverified before SSRF-fetching JWKS

**File:** `topazd/authorizer/impl/jwt.go:56-188`

```go
jwtTemp, err := jwt.ParseString(bearerJWT, jwt.WithVerify(false))  // L59
...
jwtKeysURL, err := s.jwksURLFromCache(ctx, jwtToken.Issuer())       // L90
...
req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)  // L163
resp, err := client.Do(req)                                                            // L170
```

The issuer is read from an *unverified* parse of the token. There is no allow-list (`jwt.WithIssuer` / `jwt.WithAudience` / configured trusted-issuers list). Consequences:

- **Identity spoofing.** Mint a self-signed JWT with `iss=https://attacker.example`, host a matching JWKS, and the authorizer accepts the asserted `sub` as the authenticated identity used as `input.user` in policy. Every policy that trusts the identity context is compromised.
- **SSRF.** Topaz issues `GET <issuer>/.well-known/openid-configuration` and follows the `jwks_uri` in the response. The `http.Client` is bare (no timeout, no redirect policy, no host filter). An attacker can probe internal services, scan cloud metadata (`http://169.254.169.254/...`), and pivot through redirects.
- **Cache poisoning.** First attacker to seed an issuer wins for `jwtMinRefreshInterval = 15 * time.Minute`.

**Fix:** Add `jwt.allowed_issuers` and `jwt.audience` config. Reject tokens whose issuer isn't in the allow-list *before* any network call. Set `http.Client{Timeout: ...}`, install a `CheckRedirect`, restrict to `https`, and block RFC1918 / loopback / link-local hosts. Refuse `jwks_uri` whose host differs from the validated issuer host.

---

## High

### H1. Non-constant-time API key comparison (timing oracle)

**Files:** `topazd/authentication/middleware.go:99`, `topazd/authentication/authentication.go:50`

```go
if _, ok := a.cfg.APIKeys[basicAPIKey]; ok { ... }
```

API keys are validated via Go map indexing, which uses byte-by-byte memcmp and returns early on the first mismatch. With enough samples a remote attacker can recover the key character-by-character. There is no `crypto/subtle.ConstantTimeCompare` anywhere in the repo.

**Fix:** Iterate `cfg.APIKeys` and OR together `subtle.ConstantTimeCompare([]byte(basicAPIKey), []byte(k))` results so latency is independent of any match. Better: store SHA-256 digests of keys at load time and compare digests in constant time.

### H2. Bearer credential logged at trace level

**Files:** `topazd/authentication/middleware.go:95`, `internal/grpc/middlewares/tracing/tracing_middleware.go:41`

```go
a.logger.Trace().Err(err).Str("auth_header", authHeader).Msg("failed to parse basic auth header")
```

`authHeader` is the raw `Authorization` header (`Basic <base64(key)>` or `Bearer <token>`). Trace level is commonly enabled during auth debugging — exactly when the wrong values are most likely to be persisted to log aggregators. The tracing middleware additionally logs `Interface("request", req)`, which includes the JWT for `IdentityType_IDENTITY_TYPE_JWT` requests.

**Fix:** Log only the scheme, the length, or a fixed-prefix hash. Redact the `identity` field in request dumps.

### H3. pprof endpoints have zero authentication

**File:** `topazd/debug/debug.go:33-46`

```go
pprofServeMux := http.NewServeMux()
pprofServeMux.HandleFunc("/debug/pprof/", pprof.Index)
...
```

The debug server is enabled by config flag and registers all pprof handlers without auth. A heap dump on a live process can expose in-memory tokens (the auth map keeps API keys as plain strings — `middleware.go:18,29`).

**Fix:** Require loopback bind by default, refuse non-loopback unless `--debug-allow-public` is explicit, and wrap with the API-key middleware. Same applies to `/metrics`.

### H4. Default service config binds every API to `0.0.0.0`

**Files:** `pkg/config/templates.go:147,150,156,163,202,209,249,256,297,304,342,353,365,372`, `topazd/service/builder/service_manager.go:101`

Including the unauthenticated `metrics` endpoint and the `debug_service` (when enabled). Pprof exfiltration to anyone who can reach the host is then a single misconfigured firewall away.

**Fix:** Default `debug_service` and `metrics` to `127.0.0.1`. Document the implication of binding them publicly. Either authenticate or restrict `/metrics`.

### H5. HTTP gateway transports credentials in plaintext when TLS isn't configured

**Files:** `topazd/service/builder/service_factory.go:149-153`, `service_manager.go:243-251`, `service_manager.go:110-116`

```go
config.Gateway.HTTP = !config.Gateway.Certs.HasCert()
if config.Gateway.HTTP { return ... }
```

With `config-no-tls.yaml` as a supported topology, `Authorization: basic <APIKey>` is sent in clear text. No startup warning, no `insecure_listener: true` opt-in.

**Fix:** Refuse to start with API keys configured but no TLS; or require an explicit `insecure_listener: true`. Emit ERROR-level logs at startup when binding plaintext listeners that carry credentials.

### H6. CLI `--insecure` defaults to true for `topaz template install`

**Files:** `topaz/clients/authorizer/client.go:19`, `topaz/clients/directory/client.go:24`, `topaz/cmd/templates/install.go:117`

```go
cmd.Insecure = true
if cmd.ClientConfig().NoTLS {
    cmd.Insecure = false
    cmd.Plaintext = true
}
```

A *documented* workflow runs with full TLS verification disabled. The flag has a short alias `-i`, an env-var bind `TOPAZ_INSECURE=true` that's sticky across a shell session, and is not marked hidden. Production CI/CD shells can silently inherit it.

**Fix:** Never default insecure for any installed/applied template flow. Make `--insecure` long-form-only, drop the env var or restrict its scope, and print a prominent warning on every invocation.

### H7. CORS allow-list has a missing dot — matches attacker-registrable subdomains

**Files:** `pkg/config/templates.go:188-189`, `pkg/config/schema/config.yaml:96-97`, `topazd/service/builder/defaults.go:10,30-39`

```yaml
- https://*.aserto.com
- https://*aserto-console.netlify.app   # ← no leading dot
```

The pattern `*aserto-console.netlify.app` matches `evilaserto-console.netlify.app` — an attacker can register that Netlify subdomain. The `Authorization` header is in `AllowedHeaders`, so authenticated cross-origin requests are allowed. Combined with C1 (no auth on `/api/v1/authorizers`), a browser on the attacker's site can exfiltrate the API key.

**Fix:** Tighten to `https://*.aserto-console.netlify.app` (with leading dot wildcard). Make the default localhost-only and require operators to override.

### H8. Dockerfile runs as root, uses floating `alpine` tag

**File:** `Dockerfile:1, 30-31`

```dockerfile
FROM alpine
...
ENTRYPOINT ["./topazd"]
```

No `USER` directive — container runs as UID 0. Base image is untagged and undigested — each build pulls a different upstream image, breaking reproducibility and adding supply-chain risk. Volumes `/config`, `/certs`, `/db`, `/decisions` inherit root ownership.

**Fix:**

```dockerfile
FROM alpine:3.20@sha256:<digest>
RUN addgroup -S topaz && adduser -S -G topaz topaz
USER topaz
```

### H9. gRPC reflection enabled with built-in anonymous override

**Files:** `topazd/service/builder/service_factory.go:67`, `topazd/service/builder/health.go:28`, `pkg/config/topaz_config.go:114-121`

```go
reflection.Register(grpcServer)
```

Plus the default config injects an override that *explicitly* sets `enable_anonymous: true` for `grpc.reflection.v1*.ServerReflection.ServerReflectionInfo`. Unauthenticated callers can enumerate the full RPC surface, message types, and field names — straight reconnaissance handed to attackers.

**Fix:** Make reflection opt-in (`debug_service.enable_reflection`); default off. Do not auto-inject the anonymous override.

---

## Medium

### M1. Rego query injection via `PolicyContext.Path` / `Decisions`

**File:** `topazd/authorizer/impl/authz-is.go:42-58`

```go
rule := fmt.Sprintf("data.%s.%s\n", req.GetPolicyContext().GetPath(), decision)
query := fmt.Sprintf("x%d = %s\n", i, rule)
```

Both `Path` and each `Decision` are concatenated unescaped. The only check is that the result parses as valid Rego. A caller can craft a `Decision` containing newlines and a follow-up rule (e.g., `bar\nx99 = data.system`) to reference arbitrary `data.*` paths and leak policy/data outside the nominal decision array. Same pattern in `authz-decisiontree.go:188-196`.

**Fix:** Validate `Path` with `^[a-zA-Z_][a-zA-Z0-9_.]*$` and each decision with `^[a-zA-Z_][a-zA-Z0-9_]*$` before interpolation, or build the Rego AST programmatically with `ast.MustParseRef` / `ast.NewExpr`.

### M2. `Query` / `Compile` evaluate arbitrary Rego against the live store

**Files:** `topazd/authorizer/impl/authz-query.go:36-48`, `authz-compile.go:36-47`

A caller authenticated with just an API key can submit `data.identity` (etc.) and read everything in the policy/data store, including identity records and decision-log inputs. Per-design, but the risk is undocumented and there's no separate scope.

**Fix:** Gate `Query` / `Compile` behind a distinct authentication scope; default them off and require explicit opt-in. Restrict referenced packages to an allow-list when enabled.

### M3. No mTLS client authentication option

**Files:** `topazd/service/builder/service_factory.go:243-260`, `pkg/config/schema/config.yaml` (`certs` blocks)

`prepareGrpcServer` only sets *server* TLS. There's no code path that wires `ClientCAs` or `ClientAuth = tls.RequireAndVerifyClientCert`, despite a `tls_ca_cert_path` per service and an unused `APIKey.Account` field at `pkg/config/topaz_config.go:43-46`. Auth reduces to a single shared bearer token over TLS — no per-caller identity, no revocation, no rotation per consumer.

**Fix:** Add an `mtls` option that enables required client certs and maps cert subjects to `Account` identity.

### M4. No explicit `tls.Config.MinVersion` or cipher list

**Files:** `topazd/service/builder/service_factory.go:155-160`, `service_manager.go:114,244`

`tls.Config` comes from `go-aserto`'s `Certs.ServerConfig()`. Topaz never sets `MinVersion`, `CipherSuites`, `CurvePreferences`, or `ClientAuth`. Defense-in-depth is missing — compliance regimes will not accept "the dependency probably does the right thing."

**Fix:** Set `MinVersion = tls.VersionTLS12` (1.3 preferred) and an explicit modern cipher list at the point of use in Topaz.

### M5. Hardcoded leaf certificate serial number

**File:** `internal/certs/certs.go:71-72, 116`

```go
certSerialNumber   = 1658
...
SerialNumber: big.NewInt(certSerialNumber),
```

Every leaf cert generated by `MakeDevCert` reuses serial `1658`. Violates RFC 5280 uniqueness, breaks CRL/OCSP semantics, and trips browser pinning heuristics. The CA serial is generated correctly via `rand.Int`.

**Fix:** Use `rand.Int(rand.Reader, caMaxSerialNumber)` for the leaf too.

### M6. Cert directory created world-writable

**File:** `internal/certs/certs.go:74, 247`

```go
certDirMode = 0o777
err := os.MkdirAll(certDir, certDirMode)
```

Key files are `0600`, but the parent directory is `0777`, so any local user can plant or replace `.crt` files. With `topaz/certs/trust_darwin.go` and `trust_windows.go` adding these to OS trust stores, a local low-priv attacker can influence what becomes a trusted root.

**Fix:** Use `0o700` for the cert directory.

### M7. `gopkg.in/yaml.v3 v3.0.1` indirect dep

**File:** `go.mod:209`

Known DoS panic on malformed input (GHSA-hp87-p4gw-j4gq territory). Used here for operator config so impact is limited, but worth bumping.

**Fix:** `go get gopkg.in/yaml.v3@latest`.

### M8. JSON catalog/template URLs fetched without size limit or timeout

**File:** `topaz/cmd/templates/template.go:92-109`

```go
resp, err := http.Get(fileURL) //nolint:gosec,noctx
...
buf := bytes.Buffer{}
if _, err := buf.ReadFrom(resp.Body); err != nil { return nil, err }
```

`--templates-url` / `TOPAZ_TMPL_URL` override the default; a malicious catalog can either DoS the CLI with huge files or get the CLI to disclose local file contents via `config.FileExists(fileURL) → os.ReadFile` if the URL string also happens to be a local path.

**Fix:** Enforce `https`, set `http.Client.Timeout`, cap the response with `io.LimitReader`.

---

## Low

### L1. OPA `local_bundles.skip_verification: true` in every template

**Files:** `pkg/config/templates.go:33,60`, multiple `docs/examples/*.yaml`

Bundle signatures are disabled by default. A registry compromise or misconfigured policy URL results in unverified policy code running as the authorization brain. Default should be the secure one.

**Fix:** Default `skip_verification: false`; document signing.

### L2. Path traversal in CLI `template install`/`apply` via `cmd.Name`

**Files:** `topaz/cmd/templates/install.go:53,67`, `apply.go:26,68,87,101`

```go
templateDir := path.Join(cc.GetTopazTemplateDir(), cmd.Name)
```

`cmd.Name` is unvalidated; `topaz template apply ../../etc` escapes the template directory. CLI-only, so requires operator-controlled args, but `ConfigName` already has a regex check and `Name` does not.

**Fix:** Validate `Name` with the existing `RestrictedNamePattern`; reject `..` and path separators.

### L3. UUID v1 in request IDs leaks MAC address

**File:** `internal/grpc/middlewares/request/request_middleware.go:127`

`uuid.NewUUID()` (v1) encodes the host MAC + timestamp. Used for request/trace IDs that are returned in headers and persisted in logs — leaks host network identity.

**Fix:** `uuid.NewRandom()` (v4).

### L4. Auth-override path matching is case-insensitive prefix-based

**File:** `pkg/config/topaz_config.go:67-77`

```go
if strings.HasPrefix(strings.ToLower(path), prefix) { ... }
```

An override granting anonymous access to `/aserto.authorizer.v2.Authorizer/Info` also matches `/aserto.authorizer.v2.authorizer/infosomethingelse`. Unlikely exploitable today (gRPC paths are exact), but a footgun if a future service shares a prefix.

**Fix:** Exact-match on full method strings.

---

## Informational / clean categories

- **No `math/rand` for security-sensitive randomness.** All RNG goes through `crypto/rand`.
- **No `InsecureSkipVerify: true` in Topaz Go code.** (Set indirectly via `go-aserto.Config.Insecure` — out of tree.)
- **No hardcoded private keys / certs / DH params** checked into the repo.
- **No custom `VerifyPeerCertificate`** that weakens validation.
- **RSA key size = 4096** (`internal/certs/certs.go:73`).
- **No `encoding/xml` or `encoding/gob`** anywhere.
- **No command injection** in `topazd` (only CLI-side `exec.Command` with operator-trusted `EDITOR`/`SHELL`).
- **No SQL/NoSQL injection** — BoltDB queries are typed protobuf.
- **No zip-slip / tar-slip** in the restore code path.
- **No open redirect** — the only `http.Redirect` target is a hardcoded constant.
- **No regex DoS** — no user-supplied regex compiled.
- **No multi-tenant isolation bugs** — Topaz is single-tenant per process.
- **Sensitive on-disk artifacts use `0600`** (certs, keys, CLI config).
- **`golang.org/x/crypto v0.51.0`, `google.golang.org/grpc v1.80.0`, `golang.org/x/net v0.54.0`** are all above current known-vuln thresholds.
- **Authorization decisions are fail-closed** in the `Is` / `DecisionTree` paths (return error and zero, never synthetic `allow`).

---

## Recommended remediation order

1. **C1, C2, C3** — these three together are the realistic path from "open port" to "valid API key" to "anonymous authorizer." Fix in one PR.
2. **C4** (JWT issuer pinning + SSRF guardrails) — second PR; touches `topazd/authorizer/impl/jwt.go` and adds new config keys.
3. **H1, H2** — credential side-channels. Small focused PR.
4. **H3, H4, H5** — bind defaults and credential-over-plaintext guardrails.
5. **H6** — flip the CLI `template install` default to TLS-verifying.
6. **H7, H9** — CORS dot fix and reflection opt-in.
7. **M1, M2** — Rego construction hardening + scope for `Query`/`Compile`.
8. The remaining Medium/Low items in a hygiene PR.

---

## Files most relevant to the findings

- `topazd/authentication/middleware.go`, `authentication.go`
- `topazd/app/topaz.go`, `topazd/app/handlers/authorizer.go`, `topazd/app/handlers/config.go`, `topazd/app/console.go`
- `topazd/app/middlewares/middlewares.go`
- `topazd/authorizer/impl/jwt.go`, `authz-is.go`, `authz-query.go`, `authz-compile.go`, `authz-decisiontree.go`
- `topazd/service/builder/service_factory.go`, `service_manager.go`, `defaults.go`, `health.go`
- `topazd/debug/debug.go`
- `pkg/config/topaz_config.go`, `templates.go`, `schema/config.yaml`, `loader.go`
- `internal/certs/certs.go`
- `internal/grpc/middlewares/tracing/tracing_middleware.go`, `request/request_middleware.go`
- `topaz/clients/authorizer/client.go`, `directory/client.go`, `request.go`
- `topaz/cmd/templates/install.go`, `apply.go`, `template.go`
- `Dockerfile`, `go.mod`, `.gitleaksignore`

## Caveats

- Static review only. No runtime testing, fuzzing, or fault injection.
- The `tls.Config` constructed by `go-aserto` was not inspected — TLS findings include defense-in-depth recommendations that don't depend on its behavior.
- `charts/` was referenced in the brief but does not exist in this checkout. If Helm charts live in a separate repo, repeat the review there.
