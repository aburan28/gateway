# Auth & AuthZ Security Review — Envoy Gateway

Scope: SecurityPolicy translation (gateway-api layer + xDS translator) and
the IR types backing JWT / OIDC / BasicAuth / APIKey / ext_authz / CORS /
RBAC (Authorization).

Files reviewed:

- /home/user/gateway/internal/gatewayapi/securitypolicy.go
- /home/user/gateway/internal/gatewayapi/securitypolicy_test.go
- /home/user/gateway/internal/gatewayapi/ext_service.go
- /home/user/gateway/internal/gatewayapi/validate.go (validateSecretRef, validateExtServiceBackendReference)
- /home/user/gateway/internal/xds/translator/jwt.go
- /home/user/gateway/internal/xds/translator/oidc.go
- /home/user/gateway/internal/xds/translator/basicauth.go
- /home/user/gateway/internal/xds/translator/api_key_auth.go
- /home/user/gateway/internal/xds/translator/cors.go
- /home/user/gateway/internal/xds/translator/extauth.go
- /home/user/gateway/internal/xds/translator/authorization.go
- /home/user/gateway/internal/xds/translator/utils.go (url2Cluster / addClusterFromURL)
- /home/user/gateway/internal/xds/translator/route.go (buildXdsStringMatcher)
- /home/user/gateway/internal/ir/xds.go (SecurityFeatures, OIDC/JWT/BasicAuth/APIKeyAuth/ExtAuth, PrivateBytes)
- /home/user/gateway/internal/crypto/certgen.go (HMAC generation)
- /home/user/gateway/api/v1alpha1/{jwt,oidc,basic_auth,api_key_auth,cors,ext_auth,securitypolicy}_types.go

---

## [HIGH] JWT RemoteJWKS allowed over plaintext HTTP
**File:** internal/gatewayapi/securitypolicy.go:1112, 1176-1185; internal/xds/translator/utils.go:81; internal/xds/translator/jwt.go:155-181
**Description:** `validateJWTProvider` only checks that `RemoteJWKS.URI` parses as a request URI (`url.ParseRequestURI`); it does not require an `https://` scheme. `buildRemoteJWKS` (securitypolicy.go:1181-1185) silently maps any non-`https` URL to `ir.HTTP` and `url2Cluster` happily produces a non-TLS cluster (`tls: u.Scheme == "https"`). The API documentation for `RemoteJWKS.URI` (api/v1alpha1/jwt_types.go:107) says "HTTPS URI" but no kubebuilder validation enforces it. An on-path attacker (or one controlling the JWKS host) can serve attacker-chosen public keys, allowing trivial JWT forgery and full authentication bypass for every route protected by this provider.
**Recommendation:** Reject non-https `RemoteJWKS.URI` in `validateJWTProvider` (and the CRD via `XValidation`/Pattern); document that backends must be reachable over TLS, and when only `BackendRefs` is supplied require a `BackendTLSPolicy` (or warn loudly). Also forbid URIs whose hostname resolves to an IP literal unless TLS+SAN can be validated.

## [HIGH] OIDC Issuer / discovery fetch allowed over plaintext HTTP
**File:** internal/gatewayapi/securitypolicy.go:1423-1438, 1469, 1593-1648; api/v1alpha1/oidc_types.go:178-184
**Description:** `OIDCProvider.Issuer` is documented to "MUST be a URI ... with a scheme component that MUST be https" (oidc_types.go:179) but the CRD lacks `XValidation` for that, and `buildOIDCProvider` derives the protocol from `u.Scheme == "https"` without rejecting `http`. The discovery call `discoverEndpointsFromIssuer` (securitypolicy.go:1614-1615) issues `client.Get(fmt.Sprintf("%s/.well-known/openid-configuration", issuerURL))` with no TLS enforcement; an `http://` issuer triggers a clear-text request. A MITM on the control plane (or a self-served HTTP "OIDC provider") can return arbitrary `authorization_endpoint` / `token_endpoint` / `end_session_endpoint` values that Envoy will subsequently honor. Token endpoint, redirect, and end-session URLs can be steered to attacker-controlled hosts that exfiltrate codes / tokens.
**Recommendation:** Reject any issuer/tokenEndpoint/authorizationEndpoint/endSessionEndpoint that is not `https://` (CRD-level `XValidation` plus runtime check). In `discoverEndpointsFromIssuer`, force HTTPS and reject the call otherwise. As a defense in depth, validate that discovered endpoint hostnames share a scheme/domain with the issuer.

## [HIGH] LocalJWKS ConfigMap fallback silently picks an arbitrary key
**File:** internal/gatewayapi/securitypolicy.go:1216-1249 (specifically 1231-1240)
**Description:** When `LocalJWKS.Type == ValueRef` and the referenced ConfigMap does not have the documented `jwks` key, the loop `for _, v := range cm.Data { return v, nil }` returns whatever Go map iteration order happens to surface first. (a) The selection is non-deterministic — a user who later adds another key may flip which JWKS is used; (b) any benign-looking key (e.g. `README`, `notes.txt`) added by mistake will be parsed and accepted as a JWKS, leading either to validation failures or — worse — to silently accepting an attacker-controlled key set, since users normally trust the ConfigMap. The CRD docs (jwt_types.go:148-154) imply the fallback is "first value," which Go maps do not provide.
**Recommendation:** Remove the fallback. Require the explicit `jwks` key and return an explicit error if missing. If a fallback is desired, sort keys deterministically and require exactly one key, or accept an explicit `key` field on `ValueRef`.

## [MEDIUM] JWT claim-to-headers can be spoofed when JWT is optional
**File:** internal/xds/translator/jwt.go:119-137 + 215-221; internal/gatewayapi/securitypolicy.go:1072 (`AllowMissing: ptr.Deref(policy.Spec.JWT.Optional, false)`)
**Description:** Each provider is configured with `Forward: true` and `ClaimToHeaders` (jwt.go:127-137). When `policy.Spec.JWT.Optional == true`, `AllowMissing` is added to the requirement (jwt.go:215-220), so a request with no JWT bypasses validation. Envoy's `claim_to_headers` *append* into the request; the request's pre-existing header values are not stripped first by Envoy Gateway. A client can therefore send `X-User: admin` (or whichever header an operator wired up) and bypass the protection that the operator presumably intended by configuring `claimToHeaders`. The translator never emits a `request_headers_to_remove` for the configured header names, nor surfaces a warning when `Optional=true` is combined with `ClaimToHeaders`.
**Recommendation:** When `JWT.Optional` is true with a provider that has `ClaimToHeaders`, either (a) reject the policy in `validateJWTProvider`, or (b) inject a `request_headers_to_remove` (per route) for every configured claim header so the client cannot inject it. Document the risk in the field godoc on `JWT.Optional`.

## [MEDIUM] CORS `AllowCredentials=true` permitted alongside wildcard / `"*"` origin
**File:** internal/gatewayapi/securitypolicy.go:993-1024 (buildCORS), 1026-1034 (wildcard2regex); internal/xds/translator/cors.go:144-177; api/v1alpha1/cors_types.go:27-76
**Description:** The CRD accepts the lone `"*"` (cors_types.go pattern allows `^\*$`) and `https://*` patterns, and translation always sets `AllowCredentials = c.AllowCredentials` (cors.go:167) without checking origins. Per the Fetch CORS spec, `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true` is rejected by browsers, but the wildcard-to-regex conversion turns `"*"` into `.*` which is treated as `SafeRegex` matching any origin and *echoed back as the actual origin*, sidestepping the browser check. An operator-misconfiguration here permits cross-site credential theft / CSRF against credentialed endpoints. The TODO at cors_types.go:73-75 acknowledges the issue but it remains un-mitigated.
**Recommendation:** Reject configurations where `AllowCredentials=true` is set together with any wildcard-bearing origin in `validateSecurityPolicy`. Add an `XValidation` on `CORS` to forbid the combination, and document the constraint.

## [MEDIUM] CORS wildcard origin regex is not strictly anchored at the scheme boundary
**File:** internal/gatewayapi/securitypolicy.go:1030-1034 (wildcard2regex)
**Description:** `wildcard2regex` only escapes `.` and replaces `*` with `.*`. Envoy `StringMatcher.SafeRegex` is full-match (RE2) so a pattern like `https://*.example.com` becomes `https://.*\.example\.com` and full-matches `https://attacker.com.example.com` — which is the intended hostname semantics, *but* it also matches `https://attacker-example.com` *only if* the user writes `https://*example.com` (the wildcard rule lets `*example.com` through the CRD pattern). More importantly, an origin like `https://*.example.com:8080` matches `https://x.example.com:8080` but also `https://x.example.comX8080` will not match (good); however `https://*` becomes `https://.*` which matches any HTTPS origin — operators commonly do this thinking it means "any subdomain". No port boundary is enforced when the origin pattern has no port (allowing arbitrary port).
**Recommendation:** Convert the wildcard form to a stricter regex (e.g., disallow `.*` from crossing a `.`/`:` boundary by emitting `[^.:]+` for a label-level wildcard, or only accept exactly one leading `*.` label). Add unit tests for adversarial origins (`https://evil.example.com.attacker.tld`, `https://x.example.com:9999`, `https://x.example.commm`).

## [MEDIUM] Token endpoint validator rejects IPv4 literals but allows IPv6 literals and `http://`
**File:** internal/gatewayapi/securitypolicy.go:1698-1718 (validateTokenEndpoint)
**Description:** `validateTokenEndpoint` only fails when the hostname is an IPv4 literal (`ip.Unmap().Is4()`); IPv6 literals (e.g. `[::1]`) and HTTP scheme are accepted. The token endpoint is later embedded in the OAuth2 `TokenEndpoint` URI and used to build a cluster (`url2Cluster`, oidc.go:113-122 / 467). An `http://[::1]:5000/token` token endpoint would be honored silently, defeating the IPv4 guard and allowing in-cluster localhost / link-local exfiltration paths.
**Recommendation:** Reject all IP literals (IPv4 + IPv6) and require `https` scheme. Apply the same checks to `AuthorizationEndpoint`, `EndSessionEndpoint`, `RemoteJWKS.URI`, and `OIDCProvider.Issuer`.

## [MEDIUM] OIDC `DisableTokenEncryption` is exposed as a simple boolean — fail-open security toggle
**File:** internal/gatewayapi/securitypolicy.go:1334-1336, 1374-1376; internal/xds/translator/oidc.go:198; api/v1alpha1/oidc_types.go:144-148
**Description:** When `DisableTokenEncryption=true`, access/ID tokens are stored unencrypted in client cookies (`PreserveAuthorizationHeader` / `DisableTokenEncryption` go straight through). Anybody able to read the user's cookies (XSS, malicious browser extension, log capture, shared device) gets the bearer token. There is no warning event when a SecurityPolicy enables this option, no admission-time policy to forbid it, and no requirement that `Secure`/`HttpOnly` be set together.
**Recommendation:** Default remains false (good). Emit a policy status warning whenever `DisableTokenEncryption=true`, and consider gating it behind an EnvoyProxy-level toggle so cluster admins can opt-out. Add CRD documentation that emphasizes the risk.

## [MEDIUM] OIDC SameSite policy not constrained: `None` accepted without enforcing Secure
**File:** internal/xds/translator/oidc.go:252-286 (buildSameSite / buildCookieConfigs); api/v1alpha1/oidc_types.go:237-253
**Description:** The translator forwards user-chosen `SameSite` verbatim. `SameSite=None` requires `Secure`; Envoy will emit the cookie without `Secure` when the request is HTTP, and the browser will silently drop it (broken auth) — or worse, on environments with mixed scheme handling (TLS-terminating proxies that forward as HTTP), the cookie may be set in clear contexts and leak. The OIDC CRD does not require a corresponding `Secure` opt-in.
**Recommendation:** When `SameSite=None`, refuse the policy unless the listener is HTTPS-only or expose an explicit `Secure` field and require it true. Document that SameSite=None must be paired with HTTPS listeners.

## [MEDIUM] ExtAuth `FailOpen=true` can mask validation errors and let traffic through unauthenticated
**File:** internal/gatewayapi/securitypolicy.go:736-744, 910-921 (`shouldFailOpen`); internal/xds/translator/extauth.go:97-104
**Description:** During translation, if **only** ExtAuth fails (`extAuthErr != nil && !hasNonExtAuthError`) and `policy.Spec.ExtAuth.FailOpen=true`, the translator deliberately *skips* installing the 500 direct response so that traffic is allowed without the ExtAuth filter (securitypolicy.go:739-744). Combined with `extauthv3.ExtAuthz.FailureModeAllow=true` (extauth.go:102-104), an operator who set `FailOpen` to tolerate transient backend outages also tolerates configuration errors that effectively disable authentication entirely. The CRD field docstring (ext_auth_types.go:47-57) warns about "fail-closed approach" but the dual semantics (config-time skip + runtime allow) are not documented.
**Recommendation:** Split into two fields — one for transport failures (runtime `failure_mode_allow`) and one for build-time errors. Default the build-time behavior to fail-closed regardless of `FailOpen`. At minimum, log a high-severity event/condition whenever an invalid-policy ExtAuth fail-open path is taken, and surface it in policy status.

## [MEDIUM] OIDC client ID can be configured as a plaintext field (not a Secret)
**File:** api/v1alpha1/oidc_types.go:23-29; internal/gatewayapi/securitypolicy.go:1282-1298
**Description:** `OIDC.ClientID` (string) and `OIDC.ClientIDRef` (Secret) are alternates. While client IDs are not strictly secret in the OAuth2 spec, exposing them in CRDs creates an information disclosure path (logs, Git, RBAC-broad list operations on SecurityPolicy). More concerning: identical plumbing for `ClientID` could tempt mis-typed copy/paste of the secret into `ClientID`. The plaintext path is convenient but should be discouraged.
**Recommendation:** Document the recommendation to use `ClientIDRef` in production. Optionally add an EnvoyProxy-level toggle to forbid plaintext `ClientID`.

## [LOW] OIDC discovery cache caches errors permanently (per translation), masking transient outages
**File:** internal/gatewayapi/securitypolicy.go:1575-1696
**Description:** `fetchEndpointsFromIssuer` caches both success *and* failure (`Set(issuerURL, nil, err)` at 1585). The cache is scoped to a single translation, so subsequent reconciliations retry; however during a single translation a transient failure once will block discovery for all SecurityPolicies sharing the issuer, even though the backoff (5s) above could have succeeded a second time. The comment at line 1651-1652 acknowledges this scope and there's a downstream retry on next reconcile, so the security impact is small — primarily a denial of correct configuration.
**Recommendation:** Don't cache errors (only cache successful configs), or cache errors with a much shorter TTL than successes. Add a TTL bound (e.g., 5 min) and a max-entries cap to prevent cache poisoning by an attacker who can churn many issuer URLs.

## [LOW] OIDC HMAC secret never rotates
**File:** internal/gatewayapi/securitypolicy.go:1343-1355; internal/crypto/certgen.go:299-313
**Description:** `oidc-hmac` is generated once by the certgen job (32 random bytes from `crypto/rand`, which is fine). The code comment at securitypolicy.go:1345-1346 admits rotation is TODO. Long-lived HMAC keys signing user session cookies are problematic because compromise of one secret can be replayed indefinitely; without forward secrecy, every issued cookie is potentially valid forever.
**Recommendation:** Implement key rotation (multi-key acceptance during rotation window), and document operator-driven rotation procedure.

## [LOW] BasicAuth uses unsalted SHA1; only {SHA} accepted
**File:** internal/gatewayapi/securitypolicy.go:1814-1843 (validateHtpasswdFormat); api/v1alpha1/basic_auth_types.go:14-28
**Description:** Envoy's `basic_auth` filter only supports unsalted SHA1 (`{SHA}base64sha1`), which is what `validateHtpasswdFormat` correctly enforces. SHA1 is broken for collision resistance but for short passwords the larger risk is rainbow-table lookup since the hash is unsalted. The validator correctly rejects bcrypt/`crypt`/`{plain}`. This is an Envoy filter limitation, not an Envoy Gateway bug, but it's worth flagging.
**Recommendation:** Document that BasicAuth.Users requires strong, unique passwords because the underlying digest is unsalted SHA1. Track Envoy upstream support for stronger algorithms (bcrypt) and adopt when available.

## [LOW] API key sanitize defaults to false; API keys forwarded to upstream by default
**File:** internal/xds/translator/api_key_auth.go:159-167; api/v1alpha1/api_key_auth_types.go:32-36
**Description:** If `Sanitize` is unset, `HideCredentials=false`, so the API key header/query/cookie is forwarded to the upstream. Most upstreams do not need the raw API key once the gateway has validated it; forwarding by default risks the upstream logging it (e.g. nginx access logs of query params).
**Recommendation:** Default `Sanitize=true` (breaking change candidate), or at minimum document the security implication and recommend `Sanitize=true` together with `ForwardClientIDHeader` for identity propagation. Encourage `Headers` over `Params` (query string keys end up in access logs).

## [LOW] OIDC `PassThroughAuthHeader` skips OIDC entirely when *any* configured JWT header is present, even unverified
**File:** internal/xds/translator/oidc.go:233-235, 332-364 (buildHeaderMatchers); internal/gatewayapi/securitypolicy.go:412-428
**Description:** When `PassThroughAuthHeader=true`, the OAuth2 filter is bypassed for requests bearing matching headers, expecting the downstream JWT filter to validate. The gateway requires that a JWT provider be configured with header extraction (securitypolicy.go:412-428), but if the JWT filter is also `Optional` (`AllowMissing` requirement), any request with a literal `Authorization: Bearer anything` skips OIDC AND passes JWT (because missing/invalid is allowed). Combined-policy mis-configuration -> auth bypass.
**Recommendation:** When `PassThroughAuthHeader=true`, require `JWT.Optional` to be unset/false. Add to `validateSecurityPolicy`.

## [INFO] JWT `Forward: true` is hardcoded
**File:** internal/xds/translator/jwt.go:132
**Description:** The JWT is always forwarded to the upstream when validated. This is the common pattern but precludes the operator from stripping the JWT before the upstream sees it (defense-in-depth in zero-trust networks). No CRD knob exists.
**Recommendation:** Add an optional `JWTProvider.StripBeforeForward` field that maps to Envoy's `Forward: false` (or use `forward_payload_header` patterns).

## [INFO] OIDC `id_token` signature not separately verified by Envoy OAuth2 filter
**File:** internal/xds/translator/oidc.go (overall flow)
**Description:** Envoy's `oauth2` filter consumes the OAuth2 authorization-code flow but does not cryptographically verify the OIDC `id_token`. Verification would require a separate JWT provider tied to the OIDC issuer. The CRD does not surface this — a user enabling OIDC may believe the id_token claims are validated.
**Recommendation:** Document the need to pair OIDC with a JWT provider whose JWKS is the issuer's JWKS, when the upstream relies on id_token claims. Long-term: have the gateway auto-emit a sibling JWT provider when OIDC is enabled.

## [INFO] OIDC redirect URL allows `%REQ(x-forwarded-proto)%` template — depends on operator trusting XFP
**File:** internal/gatewayapi/securitypolicy.go:43, 1520-1538 (extractRedirectPath)
**Description:** The default redirect URL uses `%REQ(x-forwarded-proto)%`. If the proxy trusts `X-Forwarded-Proto` from the client (default `useRemoteAddress`/`numTrustedHops` settings matter), the OIDC redirect URL scheme is attacker-controlled, which can downgrade redirects to `http://...`. Envoy Gateway's general listener defaults are reasonably safe, but the security boundary is not documented here.
**Recommendation:** Document the dependency on a trustworthy `X-Forwarded-Proto` (i.e., the gateway should be the TLS terminator or sit behind a trusted proxy). Consider defaulting to `https://%REQ(:authority)%/oauth2/callback`.

---

## Reviewed, no issues found

### CrossNamespace handling
- `validateSecretRef` is called with `allowCrossNamespace=false` for OIDC `ClientIDRef`, OIDC `ClientSecret`, BasicAuth `Users`, and APIKeyAuth `CredentialRefs` (internal/gatewayapi/securitypolicy.go:1287, 1300, 1736, 1791). Cross-namespace secret references are blocked with a clear error message (validate.go:929-977).
- JWT LocalJWKS ConfigMap is resolved only from `policy.Namespace` (securitypolicy.go:1226) — no cross-namespace risk.
- Cross-namespace `BackendRefs` for OIDC provider / RemoteJWKS / ExtAuth are validated via `validateExtServiceBackendReference` which enforces ReferenceGrant (validate.go:1070-1091).

### CRD-level enums and basic shape
- `OIDC.OIDC` enforces "exactly one of clientID/clientIDRef" via XValidation (oidc_types.go:18).
- `JWTProvider` requires exactly one of `remoteJWKS`/`localJWKS` (jwt_types.go:30-31).
- `LocalJWKS` requires exactly one of `inline`/`valueRef` matching the discriminator (jwt_types.go:133).
- TCP routes reject HTTP-only policies (`validateSecurityPolicyForTCP`, securitypolicy.go:446-465).

### Authorization (RBAC) translation
- `authorization.go` deny-by-default behaviour is correct: `defaultAction = denyAction` unless explicitly set to `Allow` (line 287-290).
- Empty matcher list correctly falls through to `OnNoMatch`/default (lines 313-318).
- JWT principal matching uses dynamic metadata from `envoy.filters.http.jwt_authn` keyed by provider name (line 384-389) — safe against client header injection because metadata is populated only after JWT validation.
- IP-CIDR predicates validated via `parseCIDR` and `validateCIDRs` (securitypolicy.go:467-475, 2092-2099).

### ExtAuth
- `FailureModeAllow` defaults to false (extauth.go:102-104) — fail-closed is the default and `FailOpen` is an explicit opt-in.
- TransportApiVersion is V3 (extauth.go:99).
- Per-route check-settings carry only context extensions; no auth-cookie leakage in the configuration itself.

### Secret redaction
- `ir.PrivateBytes` (xds.go:87-112) redacts on MarshalText/String/JSON for OIDC ClientSecret, OIDC HMACSecret, BasicAuth Users, APIKeyCredential Client/Key, ContextExtension Value. Good defense against accidental logging.

### HMAC generation
- `generateHMACSecret` (crypto/certgen.go:299-313) uses `crypto/rand` and produces 32 bytes — adequate strength.

### API key handling
- Duplicate API keys across CredentialRefs are rejected at translation time (securitypolicy.go:1746-1748). Duplicate client IDs are skipped (1741-1743).
- Sources are validated to be mutually exclusive — only one of headers/params/cookies per ExtractFrom (securitypolicy.go:477-487).

### CORS
- `buildXdsStringMatcher` for CORS uses Envoy `SafeRegex` (RE2 full match), preventing partial-substring origin matches. Wildcard semantics still need tightening (see medium finding above).

### Envoy OAuth2 PKCE / state / nonce
- Envoy's oauth2 filter handles state (CSRF), nonce, and PKCE code_verifier internally. `CodeVerifierCookieConfig` is emitted (oidc.go:284). CSRFTokenTTL is configurable via OIDC CRD.

### Constant-time comparison
- All credential comparisons (basicauth, api_key_auth) are delegated to Envoy filters which use constant-time comparisons internally. No Go-level credential comparison happens in the gateway.

