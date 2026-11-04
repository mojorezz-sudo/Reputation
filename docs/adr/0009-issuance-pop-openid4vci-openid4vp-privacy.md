# ADR 0009 — Holder key possession at issuance and the path to OpenID4VP privacy

Status: Proposed (stacked draft PR; must be reviewed before merge)
Date: 2026-11-04
Tracks: #16 (issuance security), #14 (unlinkability), #13 (production hardening)
Predecessors: ADR-0006 credential baseline; ADR-0008 sandbox verifier

## 1. Product security invariant

Two independent cryptographic boundaries are necessary:

ISSUANCE:
A server-verified wallet session -> issuer-generated one-time c_nonce -> holder proves possession of the new credential key -> issuer computes reputation for the server-verified wallet -> issuer signs a credential bound to that key.

PRESENTATION:
Verifier identifies itself -> verifier-generated one-time nonce -> holder signs a proof bound to audience, nonce and exact credential -> verifier checks issuer, credential validity, holder key, nonce, audience, policy, and status.

Each presentation nonce is unique **per verifier request**. Reusing a credential for legitimate *new* requests is allowed; replaying a previously signed proof is forbidden.

A nonce for issuance is not interchangeable with a nonce for presentation. A valid wallet-control signature does not authorize arbitrary holder-key substitution.

## 2. Implementation delivered in this draft

- A 256-bit random issuance c_nonce and short expiry, stored with opaque authenticated holder session and a previously verified ownership result.
- An issuer-audience-bound ES256 proof of possession, explicitly typed openid4vci-proof+jwt, with a public P-256 JWK, nonce and issued-at.
- Atomic one-time challenge consumption bound to the original holder session. Wrong session does not burn the legitimate challenge. An invalid same-session proof consumes it.
- Proof signature verified against the public key in the signed proof header, with algorithm, audience, nonce and time checks.
- The key from the verified proof is the **only** key supplied to the credential signer by the coordinator. The client cannot inject a different key after proof validation.
- Signed per-credential id / JWT jti for rotation and revocation bookkeeping.
- Development-only credential status registry keyed by the token hash and issuer / issuer-key scope. Revocation is testable end to end; unknown status fails closed.
- Real-crypto end-to-end tests that verify a newly issued credential at the existing sandbox verifier.

**This is an OID4VCI-shaped issuance proof, not a full interoperable OpenID4VCI server.** The OAuth 2.0 authorization server, token endpoint, credential configuration metadata, actual nonce endpoint transport, client authentication and interoperability suite are not implemented.

The wallet ownership result and holder session are server-owned inputs. Passing an untrusted JSON object with ok=true into a production issuance route would negate our security model. The in-memory stores are for development only.

## 3. OpenID4VP 1.0 integration decision

We will replace (not disguise) the current proprietary sandbox presentation response with a conformant OpenID4VP profile before external pilots.

Choose ONE explicit transport profile for the first supported wallets and verify against its normative semantics:

A. Cross-device / direct_post.jwt
- Verifier request: authenticated verifier client_id, fresh nonce, response mode, response URI and DCQL query.
- Wallet validates verifier identity and request/redirect origins, consents to requested disclosure, and signs the presentation bound to client_id + nonce.
- Verifier checks request correlation, VP token format, nonce, audience, issuer trust, holder binding, validity and status; reject replay through durable store.
- Encrypt responses to a verifier key where appropriate; strict redirect/response URI checks and key rotation.

B. Browser Digital Credentials API (DC API)
- For supported unsigned DC API requests, OpenID4VP relies on browser-provided origin binding; client_id is omitted.
- For signed DC API requests, validate the verifier request and expected origins.
- The *presentation audience is the string "origin:" + trusted browser origin*, NOT the client_id. Never silently reuse direct_post audience rules for DC API.
- Adopt only after testing browser and wallet interoperability and threat models.

Do not advertise OpenID4VP support until wallet interoperability tests pass.

## 4. Privacy design — separate disclosure from unlinkability

| Technology | Claim minimization | Cross-verifier unlinkability | Issuer-verifier unlinkability | Decision |
| --- | --- | --- | --- | --- |
| Plain VC JWT (today) | Poor: the credential token is disclosed | No: credential bytes, jti, holder key and claims correlate | No | Sandbox only |
| SD-JWT / SD-JWT VC | Selective disclosure of designated claims | Not with repeated credential; batch credentials with new keys can reduce linkability | No in salted-hash SD-JWT | Benchmark as interoperability bridge |
| Selective-disclosure derived proofs (e.g. BBS) | Designed for selective disclosure | Potentially stronger, contingent on issuance, revealed data and stable identifiers | Assess cryptosystem, presentation proof and revocation assumptions | Research / interoperability spike |
| ZK threshold predicates / anonymous credential family | Potentially exact Boolean without revealing source signals | Possible with careful per-verifier presentation, holder secret and nullifier strategy | Needs threat-model-specific evaluation | Long-term candidate, not selected |

Do NOT claim that SD-JWT selective disclosure is zero-knowledge comparison of hidden amounts. Do NOT infer unlinkability from the absence of raw wallet addresses alone.

### Threat model to test

1. Two colluding dApps compare copies of presentation output.
2. Issuer and dApp collude to identify a wallet or credential holder.
3. Two different credentials share one public holder key or reveal precise issue/expiry timestamps.
4. A status check leaks a credential-specific identifier or the identity of the verifier.
5. Credential leaks and is presented by a thief.
6. An old wallet is bought; its historical transaction age follows the new controller.
7. A verifier demands excessive claims, links sessions with browser telemetry, or performs credential fingerprinting.
8. Multi-wallet aggregation creates a sensitive private link graph.

### Required privacy experiments

- Test same-credential presentation to two dApps; mark as *linkable* in our current profile.
- Issue a batch with distinct keys and randomized/rounded timestamps; test what remains visible (token and unique claims).
- Compare proof size, verification cost, wallet UX, library maturity, issuer trust, revocation mechanics, and cross-wallet interoperability.
- Test issuer- and verifier-collusion separately; do not mix the threat models.
- Minimize verifier-facing claim metadata: avoid revealing exact earliest activity, raw transactions, wallet addresses, detailed provider tracing or global holder IDs.
- Define short storage/log retention and user consent boundaries before collecting live wallet graphs.

## 5. Revocation and privacy

The local status registry is NOT a production revocation scheme. Calling an issuer endpoint with a unique credential hash for every verification can itself create tracking.

Evaluate the W3C Bitstring Status List v1.0 Recommendation (15 May 2025) as the initial standards-based privacy-preserving revocation path. Its status lists can be cached and checked without a direct per-credential callback to the issuer. Evaluate signed status-list integrity, list size, index correlation, cache staleness, invalidation, key rotation and freshness limits. The published 2026 v1.1 Editor's Draft is not yet a Recommendation.

A signed per-credential id/jti is useful for status bookkeeping but becomes a stable correlation handle if the JWT is revealed. An unlinkable scheme will need a different presentation/status design, not simply more random IDs.

## 6. Deployment/launch blockers

- Authenticated app session must link fresh wallet control, issuance nonce and holder proof (HTTP handler + CSRF + origin + rate limiting).
- Credential ownership result must be reconstructed from trusted server records, never from the browser.
- Persistent, atomic issuance and presentation nonce stores with TTL and multi-replica tests.
- Real revocation/status infrastructure with privacy-preserving verification.
- Audit issuer key management, credential ID uniqueness, key rotation, metadata/JWKS and issuer trust.
- OpenID4VCI 1.0 complete integration; OpenID4VP 1.0 and specific wire format compliance tests.
- Select a privacy protocol only after colluding-verifier tests pass; document unlinkability claims precisely.
- Review GDPR/EDPB considerations for any wallet linkage and retained proof data.

## 7. Next engineering milestone

1. Implement authenticated HTTP endpoints and durable nonce stores for wallet ownership and issuance.
2. Build a small OpenID4VP 1.0 interoperability spike using a standards-conformant wallet/verifier test harness, with the sandbox proof explicitly labeled proprietary until replaced.
3. Select a privacy benchmark (SD-JWT batch + alternative derived proof/ZK) and measure real collusion/correlation leakage.

## Primary normative references

- OpenID4VCI 1.0 Final: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html
- OpenID4VP 1.0 Final: https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html
- RFC 9901 SD-JWT November 2025: https://www.rfc-editor.org/rfc/rfc9901.html
- W3C Bitstring Status List v1.0 Recommendation: https://www.w3.org/TR/vc-bitstring-status-list/
- W3C VC Data Model v2.0: https://www.w3.org/TR/vc-data-model-2.0/
