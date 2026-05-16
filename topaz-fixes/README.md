# Topaz Critical Vulnerability Fixes

These patches address the four Critical findings from `TOPAZ_SECURITY_REVIEW.md`.
They were developed and built against [aserto-dev/topaz](https://github.com/aserto-dev/topaz)
@ commit `1189dc6` (`runtime-v1.16.2`). `go build ./...` and `go vet` pass.

The patches live in this repo because the review-bot's GitHub scope is limited
to `aburan28/gateway`. To upstream, apply them inside a topaz checkout:

```bash
git clone https://github.com/aserto-dev/topaz.git
cd topaz
git checkout -b security/critical-fixes
git am /path/to/0001-security-fix-four-critical-issues.patch
```

Or, for a non-git apply:

```bash
patch -p1 < /path/to/critical-fixes.diff
```

## What's in the patch

### C1 — `/api/v1/authorizers` authentication

- `topazd/app/topaz.go`: route is now wrapped with the same `ConfigAuth`
  middleware that protects `/api/v2/config`.
- `topazd/app/handlers/authorizer.go`: handler returns the `apiKey` field
  only when the request carries an authenticated user in context. Anonymous
  callers receive an empty string in that field.

### C2 — fail-closed default when no API keys are configured

- `pkg/config/topaz_config.go`: the validator's three-way switch now refuses
  to start if `auth.keys` is empty AND `auth.options.default.enable_anonymous`
  was not explicitly set to `true`. An operator who deliberately wants
  anonymous mode must opt in; the WARN log fires on every startup that hits
  that branch. All shipped test configs already meet the new requirement.

### C3 — remove hardcoded sample API keys from the schema

- `pkg/config/schema/config.yaml`: `keys: []` plus a comment instructing
  operators to generate values via `openssl rand -hex 32`.

### C4 — JWT issuer pinning + SSRF guardrails on JWKS discovery

- `pkg/config/config.go`: new `jwt.allowed_issuers []string` field. Empty list
  disables JWT identity acceptance — fail-closed.
- `topazd/authorizer/impl/jwt.go`:
  - `validateIssuer` rejects unknown issuers *before* any HTTP call.
  - `jwksURL` requires `https://` and a host on the issuer URL.
  - `safeJWKSClient` builds an `http.Client` with a 10 s timeout, an
    `http.MaxBytesReader`-capped (256 KiB) response, redirect-count cap (3),
    a redirect policy that refuses non-https hops, and a custom `DialContext`
    that resolves and rejects RFC 1918 / loopback / link-local / multicast
    addresses (DNS-rebinding defense in depth).
  - After fetching `.well-known/openid-configuration`, the discovered
    `jwks_uri` is required to be `https` *and* its host must match the
    issuer's host — a compromised well-known endpoint cannot redirect to
    a third-party JWKS.

## Operator-visible behaviour changes

- A topaz instance that previously started with an empty `auth.keys` block
  and no explicit `enable_anonymous` flag will now refuse to start. The
  error message tells the operator exactly which key to set.
- JWT identity flows now require `jwt.allowed_issuers` to be populated.
  Existing deployments that rely on `IDENTITY_TYPE_JWT` must add the
  list of trusted issuers to their config; otherwise JWT identities will
  be rejected.

## Files touched

```
 pkg/config/config.go              |   7 ++
 pkg/config/schema/config.yaml     |   9 ++-
 pkg/config/topaz_config.go        |  16 +++-
 topazd/app/handlers/authorizer.go |  17 +++-
 topazd/app/topaz.go               |   2 +-
 topazd/authorizer/impl/jwt.go     | 160 +++++++++++++++++++++++++++++++++++---
 6 files changed, 189 insertions(+), 22 deletions(-)
```
