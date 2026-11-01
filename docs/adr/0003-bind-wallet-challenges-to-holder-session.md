# ADR 0003: Bind wallet ownership challenges to a holder session

- Status: Accepted
- Date: 2026-11-01

## Context

A valid wallet signature proves control of a wallet, but a wallet-linking operation also needs to prove *which private holder/profile session* requested that link.

If a challenge is not server-side bound to the initiating holder session, a captured signed challenge could potentially be submitted in a different session and attached to the wrong profile.

## Decision

Every ownership challenge stores an opaque `holderSessionId` server-side.

The session identifier is not included in verifier-facing reputation data and is not treated as a reputation signal.

Challenge consumption is atomic with session matching:

- matching nonce + matching holder session: consume the challenge and continue verification;
- matching nonce + wrong holder session: return the same public result as an unknown/consumed challenge and do **not** consume it;
- once consumed by the correct session, the nonce cannot be reused.

## Why the session identifier is not embedded directly in the SIWE message

The holder session is application-internal state and may itself be sensitive or implementation-specific. The signed SIWE message already binds the public wallet-link intent, domain, URI, chain, nonce and validity window. The application separately binds that challenge to the authenticated/private session that requested it.

If a future architecture requires cryptographic binding to a portable holder identifier, that will be a separate design decision rather than overloading the initial application session identifier.

## Security properties

- Prevents cross-session attachment of a valid wallet proof.
- A different session cannot burn the legitimate session's challenge merely by knowing its nonce.
- Wrong-session and missing-nonce results are intentionally indistinguishable to reduce information leakage.
- Correct-session verification remains single-use before cryptographic verification, preventing concurrent replay.

## Trade-offs

- A failed same-session verification consumes the challenge and requires issuing a new one.
- Distributed deployments require an atomic backing store; the in-memory implementation is development/test only.
- Application authentication/session security remains part of the trust boundary.

## Revisit if

- holder identity moves fully client-side;
- credentials use a portable holder secret/key as the primary application identity;
- multi-device recovery requires a different holder-binding model;
- a distributed challenge store cannot provide atomic conditional consumption.
