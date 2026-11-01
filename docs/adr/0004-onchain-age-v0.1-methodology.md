# ADR 0004: OnchainAge v0.1 methodology

- Status: Accepted for prototype
- Date: 2026-11-01
- Methodology version: `onchain-age/0.1.0`

## Purpose

Define a provider-neutral, deterministic interpretation of `OnchainAge` before implementing any vendor adapter.

## Claim semantics

`OnchainAge` does **not** mean “this human has used crypto for N years.”

It means:

> At evaluation time, a currently controlled wallet has at least one qualifying, finalized, successful outbound transaction on the declared chain at or before a requested threshold date, according to the declared methodology and source coverage.

The claim does not establish continuous historical control by the same person.

## Verification question

The primitive evaluates an explicit threshold date:

`Has qualifying activity on or before YYYY-MM-DDTHH:mm:ss.sssZ?`

We intentionally avoid internal “subtract 24 calendar months” logic in v0.1 because calendar-month arithmetic creates avoidable edge cases. A higher layer can translate a verifier policy such as “24 months” into an explicit UTC threshold date and record that date in the request.

## Qualifying evidence

A transaction qualifies only when all of the following are true:

1. It belongs to the requested chain.
2. Its `from` address is the currently controlled wallet.
3. Execution status is `success`.
4. It is finalized under the adapter's declared finality policy.
5. Its timestamp is at or before the requested threshold date.

A zero-value contract call may qualify.

Inbound transfers do not qualify because they do not demonstrate a holder-authorized outbound action.

Failed transactions do not qualify in v0.1.

## Three-valued result

The result is one of:

- `satisfied`: qualifying evidence exists at or before the threshold date.
- `not_satisfied`: no qualifying evidence exists and the source declares complete history from genesis through the observed block.
- `unverifiable`: the available source coverage cannot justify either conclusion, or integrity checks fail.

### Why this matters

Partial history can still prove a positive existence claim if it contains qualifying old evidence.

Partial history cannot safely prove a negative claim. Absence of evidence from an incomplete dataset is not evidence of absence.

Therefore:

- qualifying evidence + partial coverage -> `satisfied`
- no qualifying evidence + complete-from-genesis coverage -> `not_satisfied`
- no qualifying evidence + partial coverage -> `unverifiable`

## Provider-neutral history contract

Reputation methodology consumes project-owned normalized types, not Etherscan/Alchemy/RPC response objects.

Each history result carries coverage metadata:

- provider identifier
- chain ID
- first covered block
- observed-through block
- fetch timestamp
- whether the adapter asserts contiguous complete coverage over that range

For a negative `not_satisfied` result, v0.1 additionally requires:

- `fromBlock == 0`
- contiguous coverage declared complete

## Integrity checks

The evaluator fails closed with `unverifiable` when normalized history is internally inconsistent, including:

- coverage chain does not match requested chain
- any transaction belongs to another chain
- any transaction `from` address differs from the requested holder wallet
- invalid timestamps
- negative block numbers
- coverage range is invalid

The methodology does not silently discard inconsistent rows because that could turn adapter bugs or malicious data into incorrect reputation claims.

## Determinism

For a fixed normalized history snapshot and threshold date, the evaluator must return the same result.

Provider row order is irrelevant. Qualifying evidence is selected deterministically by:

1. oldest timestamp
2. lowest block number
3. lowest transaction index where available
4. transaction hash as final deterministic tie-breaker

## Evidence disclosure

Internal evaluation may retain the evidence transaction hash/block for auditability.

A verifier-facing credential or proof does not need to disclose the transaction hash by default. The disclosure layer is a separate decision.

## Source coverage wording

Never describe this primitive as “first ever on-chain activity” unless coverage is actually exhaustive across the intended universe of chains and activity types.

For the first MVP, wording must name Ethereum mainnet and methodology/source coverage.

## Finality

The normalized transaction has an explicit `finalized` field. The provider adapter is responsible for determining finality using its documented policy. The reputation evaluator simply requires `finalized === true`.

This keeps chain/provider-specific finality logic outside the reputation methodology.

## Adversarial fixtures required

At minimum:

1. inbound-only history -> no qualifying evidence
2. failed old outbound transaction -> ignored
3. finalized successful zero-value contract call before threshold -> qualifies
4. unfinalized old transaction -> ignored
5. provider data in arbitrary order -> deterministic oldest qualifying evidence
6. partial coverage with no old evidence -> `unverifiable`
7. complete-from-genesis coverage with no old evidence -> `not_satisfied`
8. wrong-chain row -> `unverifiable`
9. wrong-from row -> `unverifiable`

## Revisit if

- smart-account user operations need a different definition of holder-authorized activity
- EIP-7702/account abstraction makes normal-transaction `from` insufficient for important wallet classes
- cross-chain aggregation becomes part of the MVP
- provider finality guarantees are too weak
- integrators require a broader definition of meaningful age than normal outbound transactions
