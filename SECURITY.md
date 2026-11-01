# Security Principles

This project treats reputation integrity and privacy as security properties.

## Hard constraints

- Never collect wallet private keys or seed phrases.
- Never custody user funds in the MVP.
- Never publish a user's linked-wallet graph by default.
- Never describe partial data coverage as universal history.
- Never treat wallet age as proof of continuous human identity.
- Never issue `AssetThreshold` from a single balance snapshot.
- Never use raw transaction count as `DeFiExperience`.
- Never accept verifier presentations without audience binding, nonce/challenge and expiry checks.
- Never invent cryptographic primitives when reviewed standards/libraries fit.
- Never deploy production-like credential issuance before independent security and privacy review.

## Threats that must have tests

1. Signature replay.
2. Presentation replay.
3. Wallet purchase / controller change.
4. Sybil wallet clusters.
5. Wash activity and circular flows.
6. Flash-loan-funded balance spikes.
7. Rented or short-lived capital.
8. Repeated dust-sized borrow/repay cycles.
9. Incomplete indexer/protocol coverage.
10. Revoked or expired credentials.
11. Verifier correlation and proof fingerprinting.
12. Issuer-key compromise.

## Reporting

Until a formal disclosure process exists, do not publish sensitive exploit details in public issues. Security-reporting instructions will be added before any public pilot.
