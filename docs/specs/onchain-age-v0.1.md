# OnchainAge v0.1 — executable semantic specification

Status: Draft for implementation and adversarial testing
Methodology ID: `onchain-age/0.1`
Initial chain: Ethereum mainnet (`chainId=1`)

## Purpose

Allow a holder to prove that a wallet they currently control has qualifying holder-initiated on-chain activity at or before a threshold date/block.

## Claim form

Prefer a threshold predicate rather than disclosing an exact first-activity timestamp:

`OnchainAge >= threshold`

Example verifier request:

`OnchainAge >= 24 months`

## What this proves

At evaluation time, the holder demonstrated current control of the wallet, and the supported Ethereum dataset contains qualifying activity attributable to that address at or before the threshold boundary.

## What this does NOT prove

It does not prove:
- the same human controlled the wallet throughout its history;
- the wallet was continuously active;
- the holder is a unique human;
- the activity was economically meaningful;
- the wallet has good creditworthiness;
- the wallet has never been compromised, sold or transferred;
- activity on unsupported chains.

## Qualifying activity v0.1

For the first implementation, qualifying evidence MUST require holder-authorized outbound Ethereum activity, not merely the address appearing in chain state.

Qualifying evidence:
- a successfully included transaction whose `from` address equals the subject wallet.

Non-qualifying as sole evidence:
- unsolicited inbound ETH transfer;
- inbound ERC-20/ERC-721/ERC-1155 transfer;
- airdrop/spam token receipt;
- contract event that merely contains the address;
- balance existing without a holder-authorized transaction.

Rationale: an attacker can cheaply send assets/events to an address without proving that the address owner acted at that time.

## Earliest evidence

`firstQualifyingActivity` is the earliest canonical successful transaction found within the supported dataset where `tx.from == subject`.

The implementation must not infer continuous ownership from this value.

## Threshold evaluation

Inputs:
- `subjectAddress`
- `chainId`
- `asOfBlockNumber`
- `asOfBlockHash`
- `asOfTimestamp`
- requested age threshold
- normalized transaction observations

Output is tri-state:
- `satisfied`
- `not_satisfied`
- `unverifiable`

Use `unverifiable` when data coverage is insufficient or inconsistent. Never convert missing data into `not_satisfied`.

## Provenance attached to result

- methodology ID/version;
- chain ID;
- as-of block number/hash;
- data adapter identifier/version;
- coverage bounds;
- first qualifying block number/hash/timestamp when retained internally;
- reason code;
- evaluation timestamp.

Exact first-activity data should not be disclosed to a verifier unless required and consented to. The default external claim is the threshold result.

## Reorg/finality handling

Production semantics must evaluate against a block considered sufficiently finalized by chain policy. Test fixtures use fixed block hashes. If the as-of block hash no longer matches the expected canonical block, the result is stale/unverifiable and must be recomputed.

## Adversarial fixtures required

1. **Inbound dust only** — old inbound transfer but no holder-signed transaction: must not establish age.
2. **Spam token only** — old unsolicited token/event: must not establish age.
3. **Old outbound transaction** — valid old holder-signed transaction: can establish age.
4. **Insufficient coverage** — provider/fixture starts after threshold: result must be `unverifiable`, not `not_satisfied`.
5. **Reorg mismatch** — stored as-of block hash differs: result must be rejected/recomputed.

## Known weakness deliberately accepted in v0.1

A purchased, transferred or compromised old wallet can inherit historical age. `OnchainAge` therefore MUST NOT be presented as identity age or continuous-person tenure. Later reputation primitives may combine additional evidence to reduce this weakness, but should not silently change the meaning of this credential.
