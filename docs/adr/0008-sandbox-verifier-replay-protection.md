# ADR 0008 — Sandbox verifier, holder binding and replay prevention

- Status: Proposed, draft PR
- Date: 2026-11-03
- Scope: Verification of OnchainAge VC JWT in a developer sandbox

## Context

A signed credential is reusable across separate verifier requests. A *presentation* is a one-time, audience-bound response. The two must be distinguished, otherwise a stolen bearer token or captured presentation could be replayed.

OpenID4VP 1.0 defines audience/client_id and request nonce binding for cryptographic holder presentations. We follow these security properties now but **this sandbox protocol is not yet an OpenID4VP 1.0 implementation**.

## Decision

1. The verifier stores a one-time random 256-bit nonce, configured audience, expiry and immutable policy snapshot.
2. The holder signs a short-lived ES256 JWT containing the nonce and a SHA-256 digest of the exact credential JWT. The JWT audience is the intended verifier.
3. The verifier obtains the credential issuer identity, issuer key ID and issuer public key from server-controlled trust configuration. Never fetch or trust keys named by an untrusted JWT.
4. Verify the issuer signature and exact ES256 algorithm; enforce VC JWT type, issuer, key ID, JWT iat/exp, VC validFrom/validUntil, schema version and signed claim semantics.
5. Extract the holder P-256 public JWK from the *verified* credential cnf claim. Verify the separate holder proof signature with that key.
6. Verify proof type, ES256 algorithm, nonce, exact audience, credential hash and short validity period.
7. A single atomic store take consumes the nonce; replay fails even when the original proof remains cryptographically valid. Invalid same-verifier submissions also burn the nonce.
8. Compare the signed age threshold with the verifier policy. A credential with a strictly earlier/equal age cutoff is strong enough for the requested cutoff; chain and methodology must match.
9. Credential status checking is mandatory. If a trusted status service is unavailable or returns unknown, fail closed as unverifiable; if revoked, reject.

## Guarantees and non-guarantees

### Demonstrated in sandbox

- Cryptographic issuer signature integrity.
- Holder proof-of-possession from the credential's confirmed public key.
- Request nonce and audience binding.
- Replayed presentation detection via nonce consumption.
- Expiry checks and policy matching.
- Explicit failing closed on unknown revocation status.

### NOT guaranteed

- OpenID4VP wire compatibility, DCQL requests, wallet interoperability or discovery.
- Zero-knowledge or unlinkability. Re-presenting the same JWT/holder key leaks linkability to colluding verifiers.
- Certified key management, real revocation service or production-ready issuer trust rotation.
- Cross-instance atomicity from the in-memory store (development only).
- Cross-service holder privacy or real-world identity continuity.

## Trust and deployment gates

- Verifier issuer/public-key trust config MUST be server-owned.
- Status checking MUST use an authenticated/verifiable source, not an unconditional allow stub in production.
- HTTP entry point MUST authenticate verifier sessions and prevent CSRF, leakage in URLs/logs, replay/rate-limit abuse and cross-tenant challenge theft.
- Replace in-memory store with an atomic persistent store across application replicas.
- Add independently reviewed issuer key rotation, revocation, audit and privacy review.
- Compare this sandbox profile with production OpenID4VP / SD-JWT VC / ZK approaches before claiming interoperability or privacy guarantees.

## Test expectations

Positive: valid issuer, valid signed age claim, current credential, same holder key, nonce, audience and active status.

Negative: wrong issuer signing key, wrong kid, wrong issuer ID, substituted credential, wrong holder signing key, wrong audience, wrong nonce, expired credential, expired holder proof, overlong proof lifetime, replay, concurrent replay, expired challenge, unsupported chain, insufficient age threshold, methodology mismatch, revoked or unknown status.

## Follow-up

1. Build an actual OpenID4VP-compatible request/presentation integration with strong trust configuration.
2. Evaluate selective disclosure and unlinkability mechanisms independently of the current basic JWT format.

## References

- OpenID4VP 1.0 Final: https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html
- W3C VC Data Model 2.0: https://www.w3.org/TR/vc-data-model/
- VC JOSE/COSE: https://www.w3.org/TR/vc-jose-cose/
