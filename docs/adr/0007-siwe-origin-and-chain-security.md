# ADR 0007 — SIWE origin, clock and signature verification hardening

- Status: Proposed (PR #12, not yet merged)
- Date: 2026-11-03
- Scope: wallet ownership challenge issuance and verification
- Related: ADR 0003 (holder-session binding), issue #1, PR #12

## Problem

A cryptographically valid SIWE signature alone is not sufficient to establish a safe wallet-linking operation. We must constrain what the user signed, where it was requested, when it is valid and which chain defines any smart-account signature.

The previous implementation validated the stored message at verification time but accepted arbitrary domain and uri when issuing a challenge. It also used an EOA-only signature helper by default and did not independently reject challenge issue times substantially in the future.

## Decision

1. Challenge issuance requires a trustedOrigin derived from server deployment configuration, never user-controlled request bodies, URL query parameters or headers.
2. The SIWE domain and request URI origin must exactly match the configured origin. HTTPS is required, except HTTP on loopback for local development. URI userinfo and fragments are rejected.
3. The SIWE signing statement is fixed and explains wallet control, not arbitrary request-supplied text.
4. The verifier rejects challenges whose issued-at time is more than 30 seconds ahead of the server verification clock.
5. Signature verifier adapters receive chainId from the stored challenge, not from the caller's presentation. A chain-bound public-client adapter refuses mismatched chain contexts.
6. The EOA-only verification helper remains an explicit development/default fallback. A smart-contract wallet requires a trusted chain-configured public client with suitable ERC-1271 (and, if needed, counterfactual account) support.
7. A nonce remains session-bound and consumed atomically before cryptographic verification. An invalid same-session attempt burns the challenge; a wrong-session attempt does not.

## Implementation notes

- trustedOrigin is a server-only input. The library cannot establish whether an HTTP handler forwards attacker-controlled data as configuration. Call-site and integration review are mandatory.
- The optional now fields in challenge issuance/verification are deterministic test/clock-injection seams. Production callers must derive time from a trusted server clock.
- The in-memory nonce store is not suitable for distributed production instances. Atomic persistent storage, TTL cleanup, rate limiting and session authentication are required before deployment.
- A public client's verifyMessage behaviour depends on its version, chain state and smart-wallet capabilities; the injected wrapper itself is not a security audit.
- A valid signature proves current control at a point in time, not uninterrupted human ownership or the quality of historical reputation.

## Evidence and tests

- Trusted origin/domain/URI mismatch rejects issuance.
- HTTP for a non-loopback origin is rejected.
- Future-dated challenges beyond clock skew are rejected.
- Concurrent replay produces at most one success in the development store.
- Chain mismatch is rejected before calling an injected signature client.
- The exact signed message is passed to the chain-bound verifier.
- Existing signature, session, expiry and tampering tests remain.

CI: https://github.com/mojorezz-sudo/Reputation/actions/runs/41697771563 (successful before this documentation-only commit).

## Alternatives considered

- Allow any requested SIWE domain: rejected; creates spoofing risk at issuance.
- Validate only the signed message at verification: rejected; protects integrity of issued text but not issuer authorisation.
- Treat the EOA-only utility as supporting all wallet types: rejected; contract-account correctness is chain-dependent.
- Embed arbitrary holder identifiers in public signing text: rejected; harms privacy.

## Residual risks and blockers

| Item | Severity | Status |
| --- | --- | --- |
| Server-origin and chain policy enforced at the authenticated HTTP boundary | High | Pending integration |
| Distributed atomic nonce storage | High | In-memory store is development-only |
| End-to-end ERC-1271 tests against declared chains | High | Pending |
| Challenge rate limiting and abuse controls | High | Pending |
| Session fixation, CSRF and reverse-proxy origin handling | High | Not yet assessed at HTTP level |
| Never allow untrusted caller input to choose the trusted clock | High | Pending integration |
| Credential verifier and privacy review | High | Separate workstream |
| Multi-tenant origin and wallet recovery policies | Medium | Deferred |

## Revisit when

- Production HTTP/API endpoints are introduced.
- Multiple public origins or environments are supported.
- Smart-contract account verification is required in a pilot.
- Stateless or distributed holder sessions replace the in-memory flow.

## References

ERC-4361: https://eips.ethereum.org/EIPS/eip-4361

viem publicClient.verifyMessage: https://viem.sh/docs/actions/public/verifyMessage
