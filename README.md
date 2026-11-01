# Reputation

Privacy-preserving, portable on-chain reputation infrastructure.

## Product thesis

Reputation should be expressed as narrowly scoped, verifiable credentials rather than one global score.

**North-star promise:** _Prove what matters. Reveal nothing else._

## MVP goal

Demonstrate an end-to-end reputation proof flow:

1. A holder connects one or more wallets and proves current control.
2. Supported on-chain history is read and normalized.
3. Deterministic reputation primitives are computed.
4. A time-bounded credential is issued.
5. A verifier requests a narrowly scoped claim.
6. The holder presents only the required proof.
7. The verifier validates issuer, methodology version, freshness, audience, nonce and status.

## Initial reputation primitives

- `OnchainAge`
- `DeFiExperience`
- `LendingHistory`
- `AssetThreshold`
- `NoKnownLiquidation`

Numerical thresholds and methodologies are provisional until adversarial testing and integrator discovery validate them.

## Non-goals for the first MVP

- No universal reputation score.
- No consumer credit score.
- No lending decisions.
- No token or coin.
- No custody of user funds.
- No private keys collected.
- No public multi-wallet graph by default.
- No unnecessary personal data written on-chain.
- No custom cryptography where mature reviewed standards/libraries exist.

## Architecture principles

- Privacy by default.
- Standards first.
- Deterministic and explainable reputation rules before machine learning.
- Version every credential schema, methodology and protocol adapter.
- Treat reputation as economically valuable and therefore adversarially farmable.
- Prefer threshold proofs/selective disclosure over exact-value disclosure.
- Keep on-chain state created by this project minimal unless there is a clear security or interoperability benefit.

## Standards baseline

- W3C Verifiable Credentials Data Model 2.0
- OpenID for Verifiable Credential Issuance 1.0
- OpenID for Verifiable Presentations 1.0

## Project workflow

Product research, threat models, legal/privacy analysis and major architecture documents live in the project Google Drive.

Code, executable specifications, fixtures, tests, issues and technical ADRs live in this repository.

Major decisions should document:

- decision
- rationale
- alternatives considered
- advantages
- risks
- conditions that would trigger reconsideration

## Sprint 1 — Proof of Reputation

The first technical target is deliberately narrow:

`wallet ownership -> OnchainAge -> credential -> verifier`

Only after that flow is deterministic, replay-resistant and privacy-reviewed do we add a lending protocol adapter and `LendingHistory`.

## Security rule

A valid cryptographic proof is not enough if the underlying reputation claim is semantically wrong, manipulable or privacy-leaking. Signal integrity and claim wording are treated as security properties.

## Status

Early research and prototype stage. Nothing in this repository should yet be treated as production-ready or suitable for financial decision-making.
