# ADR 0001: Use reputation primitives, not a universal score

- Status: Accepted
- Date: 2026-11-01

## Context

A single score is easy to display but hides methodology, encourages over-broad interpretation, creates incentives to game one number and increases the risk that integrators treat the score as a general judgment about a person.

## Decision

The MVP will expose narrowly defined, versioned reputation primitives and credentials such as `OnchainAge`, `LendingHistory` and `NoKnownLiquidation`.

Integrators may compose those primitives into their own policies, but the project will not publish a universal user score in the MVP.

## Advantages

- Better explainability.
- Easier independent verification.
- Less semantic overreach.
- Easier versioning and deprecation.
- Different protocols can combine the same primitives differently.
- Reduces pressure to create opaque machine-learning scoring early.

## Risks

- Integrator experience is slightly more complex than consuming one number.
- Some customers may still ask for a single score.
- Policy composition requires good SDK ergonomics.

## Revisit if

A later score can be shown to provide clear user/integrator value without materially reducing explainability, privacy, auditability or fairness. Any future score must be optional and derived from transparent primitives.
