# ADR 0011 — SD-JWT VC pilot, atomic replay storage and derived revocation

- Date: 2026-11-06
- Status: Proposed; stacked draft PR #21, following PR #20
- References: RFC 9901 (Final November 2025), draft-ietf-oauth-sd-jwt-vc-25 (2026-11-05), OpenID4VP 1.0 Final
- Scope: experimental SD-JWT VC integration; Redis replay-storage adapters; issuer status and privacy invariants

## A. Standards profile: version-pinned, independently reviewable

RFC 9901 is a stable publication defining the selective disclosure / Key Binding JWT mechanism. SD-JWT VC is an IETF Internet-Draft, not yet a published RFC; this implementation targets draft-ietf-oauth-sd-jwt-vc-25 of 5 November 2026.

The issuer does NOT rename an existing VC JWT to dc+sd-jwt. The issuer:
- Cryptographically verifies the original issuer-signed VC 2.0 token with a pinned issuer public key, issuer identity, kid, expiration and expected signed OnchainAge schema;
- Confirms the source credential is currently valid with a trusted status source;
- Issues a new, distinct signed SD-JWT VC with typ=dc+sd-jwt, application/dc+sd-jwt, a collision-resistant vct identifier, fixed chain/methodology claims, signed cnf holder public key, _sd_alg=sha-256 and random 128-bit-salted disclosure digests;
- Hides thresholdDate and providerId behind different disclosure digests. Default presentation discloses thresholdDate only; providerId is NOT shown by default;
- Does not publish the source wallet address, original transaction evidence, source credential identifier or the new private revocation registry ID in the signed public token;
- Uses a KB-JWT of typ=kb+jwt signed by the holder key. The sd_hash is a SHA-256 hash of the exact selected serialized issuer JWT + disclosures including trailing tilde. Nonce and exact full verifier client ID are signed with short iat/exp validity;
- Rejects a forged or missing disclosure, wrong holder key, wrong audience, wrong nonce, wrong issuer key, unsupported chain/methodology, weak age evidence, expired/revoked/unknown status or mismatched SD-JWT/KB hash.

The OpenID4VP request now selects dc+sd-jwt with an exact vct_values DCQL query, require_cryptographic_holder_binding=true and matching verifier format metadata. This format selection is persisted with the nonce/state and selects the verifier-side cryptographic path after decryption. The response cannot request a different verifier format.

### Crucial privacy qualification

Selective disclosure is NOT unlinkability. Colluding verifiers can compare the reused issuer-signed JWT bytes, its signed holder public key, the disclosed threshold date or even patterns of hidden digests. Even batch credentials reissued from the same source currently share a holder key. Our tests explicitly verify that linkability exists. We make NO zero-knowledge or unlinkable-product claim.

The vct URL in this prototype is illustrative and MUST be hosted/registered in an issuer-controlled namespace with a published type definition before any interoperable pilot.

## B. Replay storage: atomically consumed server-side state

New adapters use Redis >=6.2 protocol commands:
- SET with PX and NX for a bounded TTL and collision-proof creation.
- GETDEL to atomically consume OpenID4VP state once.
- A Lua EVAL script compares an authenticated session ID and atomically deletes only for the matching holder/browser session. Wrong-session probes do not burn the legitimate request.
- Redis key names contain SHA-256 digests of 256-bit bearer tokens, never bearer tokens themselves.
- Issuer public CryptoKey objects are NOT JSON serialized. Only trusted issuer/kid selectors are stored; the actual key is restored exclusively from an independently configured server-side key allowlist.
- Credential format must be explicit in the persisted transaction to prevent legacy/SD-JWT confusion.
- Expired or unreadable Redis records fail closed; unavailable Redis does NOT silently switch to a process-local fallback.

### Test coverage and limitations

Unit tests use a deterministic atomic Redis COMMAND MODEL to exercise NX/PX/GETDEL/EVAL, concurrency across adapter instances, replay, collision, TTL, wrong-session isolation, unavailable key, corrupted metadata and network outage. They are NOT live Redis tests and do not prove durability, replica consistency or Lua portability under real load. A real Redis instance, multiple Node processes, network failures, failover, ACL and TLS are required before deployment.

Server-side issuance records still contain wallet addresses and ownership timestamps in Redis JSON values. This is sensitive! At-rest encryption, hardened Redis access controls, regional hosting, minimal retention, privacy impact review, no-eviction policy and credential/key rotation must be implemented before production. No address or token may be put in application logs or analytics.

## C. Derived-credential revocation safety

A derived SD-JWT VC must not remain valid after its source credential is revoked. The new development-only linked status registry keeps an internal parent reference and checks BOTH the derived credential and the canonical source status at verification. If either is revoked, fail. If either is unknown or unavailable, return unverifiable. This prevents using already minted derivatives as a revocation bypass in the sandbox.

This in-memory implementation is NOT a production revocation service: it retains source JWTs and could phone home to the issuer. That is a significant privacy risk. Production must publish signed, independently cacheable, privacy-preserving revocation/status information and maintain revocation lineage through issuer-side state. Evaluate the W3C Bitstring Status List v1.0 Recommendation (15 May 2025) with cache freshness, status index enumeration/fingerprinting, key rotation, revocation delay and offline validation tests. Never send per-holder credential IDs to the issuer for every verifier request.

## D. Production and conformance blockers (all open)

1. **Wallet interoperability:** no independent wallet or OpenID Foundation conformance-suite run has passed. The local harness is not proof of broad compatibility; test at least two independently maintained wallets supporting the chosen vct/profile, attestation and DCQL.
2. **Public endpoints:** no HTTPS deployment, browser origin proof, authenticated session, reverse-proxy security, CSRF, rate limit, anti-phishing UX or TLS verification is included in this PR.
3. **Redis:** real Redis 7+ integration and failure-injection tests needed; add TLS, ACL, protected master, multi-replica atomicity, durability, TTL metrics and failover scenario tests.
4. **Storage privacy:** encrypt wallet/issuance session values at rest, implement key rotation and prove that leaked Redis backups cannot map wallets to identifiers.
5. **Issuer key trust:** known trust anchors, signing key lifecycle, revocation of issuer keys, status-list signatures and clock tolerances need a formal key-management architecture.
6. **Derivation lineage:** move source/derived revocation tracking into a privacy-preserving signed status-list design with tested invalidation propagation and independent verifier caching.
7. **Unlinkability:** only claim true unlinkability after colluding verifier tests and ZK/anonymous credentials research. SD-JWT alone does not satisfy this property.
8. **Dependency risk:** SD-JWT VC draft-25 can change. Pin version, add RFC 9901/JWT test vectors, and review normative diffs before a public pilot.

## E. Acceptance policy

PR #21 remains DRAFT until a code review and full TypeScript + test CI pass. It may be used for a local development pilot but MUST NOT be represented as deployed production infrastructure, OpenID-certified interoperability or an audited privacy protocol.

PR #20 must first be reviewed and merged before #21 can be rebased to main. Neither PR is eligible for production without the external and infrastructure gates above.

## Primary references

- https://www.rfc-editor.org/rfc/rfc9901.html
- https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-25.html
- https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html
- https://www.w3.org/TR/vc-bitstring-status-list/
- https://openid.net/openid4vp-and-openid4vci-conformance-tests-are-complete-and-open-for-self-certification/
