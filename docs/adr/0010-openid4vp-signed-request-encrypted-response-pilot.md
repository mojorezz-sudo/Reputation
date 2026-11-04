# ADR 0010 — Signed OpenID4VP Request + encrypted direct_post.jwt interoperability pilot

- Status: Proposed; draft PR, not ready for production
- Date: 2026-11-04
- Baseline: OpenID4VP 1.0 Final (2025-07-09), OpenID4VCI 1.0, W3C VC 2.0
- Dependencies: merged PRs #15 and #17, issue #18 and privacy issue #19

## 1. Architectural decision

Build a **real OpenID4VP wire-profile candidate** (not the proprietary sandbox proof):

1. Verifier identification: verifier_attestation Client Identifier Prefix from Section 5.9.3, **not** redirect_uri. A redirect_uri client identifier cannot authenticate a signed Request Object. The Wallet receives a verifier-attestation JWT issued by an independently trusted authority; its signed cnf.jwk binds the verifier signing key.
2. Signed Authorization Request: JWS typ=oauth-authz-req+jwt, ES256, aud=https://self-issued.me/v2 (static wallet discovery), cryptographically random nonce and state, response_type=vp_token, response URI, requested DCQL and client metadata.
3. Transport: request_uri served by HTTPS as application/oauth-authz-req+jwt, Cache-Control:no-store. The wallet invocation URI contains only client ID and request URI; **we have implemented URI generation but have not deployed an HTTPS endpoint or an independent wallet**.
4. Credential profile: pilot jwt_vc_json (OpenID4VP Appendix B.1.3.1). We reissue a **separate** JWT VC from a cryptographically verified native VC 2.0 claim, using a fresh issuer-signed ID/JTI and the original holder key. The native application/vc+jwt is NOT silently relabeled as jwt_vc_json. This is a deliberate legacy interoperability bridge, not a change of the primary product credential format.
5. Wallet response: vp_token JSON object keyed by the DCQL Credential Query ID with a one-element array containing an ES256 signed JWT VP. Holder proof uses the full verifier client ID in aud and matches the original one-time nonce. The VP embeds only the issuer-signed, explicitly designated JWT VC.
6. Privacy/transport: Wallet encodes {state,vp_token} as a compact JWE with alg=ECDH-ES, enc=A128GCM using an ephemeral verifier public key from request metadata, and POSTs response=<JWE> as application/x-www-form-urlencoded according to direct_post.jwt.
7. Verifier validates JWE against its own private key, key ID, state, request expiration and exact one-element DCQL response. It verifies BOTH issuer and holder signatures, nonce, full audience, timestamps, credential claim semantics and status. It atomically consumes state before proof checks.
8. Anti-session-fixation: even a successful response remains *pending*. It generates a one-time 256-bit response code and MUST be explicitly confirmed from the authenticated browser session that initiated the transaction. A callback must never authenticate the browser immediately just because an external wallet posted proof.

## 2. Explicit supported subset

- One DCQL query for OnchainAge, jwt_vc_json, one matching credential, ES256.
- Verifier attestation bound to ES256 P-256 key; trusted authority verification is pinned.
- Signed Request Object with static wallet audience.
- Encrypted direct_post.jwt using ECDH-ES + A128GCM.
- ES256 JWT VC 1.0 style nested vc and ES256 signed JWT VP with nonce and aud.
- Atomic request state consumption and separate browser-session confirmation code.
- Verifier policy: issuer, known issuer public key/kid, chain, methodology, threshold, revocation status.

No arbitrary DCQL semantics, multiple credentials, mdoc, SD-JWT VC, BBS, ZK, multi-party issuance, response-by-reference, token exchange, general wallet discovery or cross-device user confirmation UX yet.

## 3. Security properties and adversarial tests

- Wrong attestation authority or verifier signing key is rejected.
- Attestation-approved response URI prevents substitution.
- Changed signed request is detected.
- Invalid, duplicated or unexpected direct_post form parameters rejected.
- Wrong JWE recipient key, alg, enc, kid or broken ciphertext rejected.
- Wrong/old state, expired transaction or replayed JWE rejected.
- Wrong holder signature, wrong full client ID audience or wrong nonce rejected.
- Legacy format JWT VC verified with pinned issuer key and schema/policy checks; unknown or revoked status fails closed.
- Response code can be consumed only by the original authenticated browser session, at most once.
- Same credential may support a new request with a new nonce/state/VP; a copied VP is not reused.
- An independently trusted attestor and service deployer must configure the actual keys; no value supplied by untrusted holder input can select a trust root.

## 4. Known limitations and portability risks

- This is **protocol-shaped, standards-aligned code tested with a local independently verifying wallet fixture**, NOT a successful interoperability test with any third-party wallet application. The term "interoperable" can be claimed only after at least two independently maintained wallet implementations and a wallet conformance suite have passed. A live HTTPS request URI endpoint / response handler has not been deployed.
- Verifier-attestation sub uses the full prefixed client ID per Section 12. Section 5.9.3's description of the original identifier is ambiguous; validate real wallet behavior before external release and normalize only via a documented profile/erratum.
- VC 2.0 direct JWT and OpenID4VP jwt_vc_json appendix legacy nested JWT are distinct encodings. Test wallets' format support rather than assume VC2 vc+jwt compatibility.
- This standalone prototype implements specific output validations and does NOT provide comprehensive generic OpenID4VP/DCQL parsers. Additional credential formats need separate implementations and conformance vectors.
- Holder's P-256 public JWK, JWT VC token bytes, IDs and attributes remain **linkable** across verifiers. The use of JWE encrypts transport only; it does not achieve unlinkability or true ZK.
- Any issuer-verifier correlation through status checking remains possible; our current local registry is a development fixture. Investigate cacheable W3C Bitstring Status List 1.0.
- The in-memory request, pending-result and status stores are **not** atomic across production replicas, and do not provide durable retention/audit/recovery.
- A public HTTP handler must bound request body size, enforce TLS, origin, authentication/session, rate limits, response code confirmation/CSRF and conservative caching and logging.
- Use legitimate verifier attestation trust anchors, revocation and key rotation before external pilots. No developer-generated test attestation may be treated as a trusted production identity.

## 5. Operational acceptance gates before any external wallet pilot

1. Provide an HTTPS request_uri endpoint serving exact signed JWS content, with an expiration policy.
2. Implement an application/x-www-form-urlencoded POST endpoint for encrypted direct_post.jwt, no-referrer/no-store, and safe continuation through a separately authenticated session.
3. Publish/distribute wallet-compatible verifier attestation trusted by the selected wallet implementations.
4. Run at least two external wallets; compare client_id handling, aud, DCQL, JWE, attestation validation and allowed credential formats.
5. Replace in-memory stores with transactional server backing and implement per-session correlation, TTL cleanup, duplicate response handling, CSRF and rate limiting.
6. Build a fully standards-compliant OpenID4VCI issuer if external issuance is required, with real OAuth2, credential metadata, nonce endpoint, format registration and wallet holder-key proof.
7. Perform independent security review of verifier key trust, response decryption, wallet key binding, revocation and privacy.

## 6. Primary normative references

- https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html (Sections 5.8–5.10, 6, 8.1–8.3, 8.6, 12, 14 and Appendix B.1.3.1)
- https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html
- https://www.w3.org/TR/vc-data-model-2.0/
- https://www.w3.org/TR/vc-bitstring-status-list/

## 7. Current market conformance profile check (2026-11-04)

OpenID Foundation completed its free OpenID4VP 1.0 + HAIP 1.0 conformance suite on 2026-08-07. The published wallet certification profiles are for **SD-JWT VC** and **ISO mDL** with `direct_post.jwt` or `dc_api.jwt`; they do NOT establish that certified wallets accept this prototype's **legacy `jwt_vc_json`** request. See https://openid.net/openid4vp-and-openid4vci-conformance-tests-are-complete-and-open-for-self-certification/ and https://openid.net/certification/certified-oid4vp-haip-final/.

Next conformance gate:
- Run an OpenID Foundation verifier conformance suite for the selected HAIP/OpenID4VP profile, and capture all verdicts as reproducible CI artifacts.
- Prioritize a separate, standards-conformant **SD-JWT VC** credential-issuance and VP adapter instead of assuming automatic compatibility with legacy JWT VC; keep the existing canonical VC 2.0 credentials distinct.
- Test two **independently maintained** wallets verified to support our selected format and verifier trust scheme; the certification list offers starting points such as eudi-dev and OID4VCgo, but support for `verifier_attestation` and our specific format MUST be confirmed separately.
- Only claim wallet interoperability when both real-world tests pass and the verifier trust anchor is accepted by those wallets.

The code in this PR remains a cryptographically tested **interoperability candidate**, not yet independently interoperable.
