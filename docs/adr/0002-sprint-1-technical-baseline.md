# ADR 0002: Sprint 1 technical baseline

- Status: Accepted for prototype
- Date: 2026-11-01

## Context

Sprint 1 needs a narrow but credible technical baseline for wallet ownership, `OnchainAge`, and the first lending adapter. The baseline must optimize for correctness and replaceability, not maximum chain coverage.

## Decision

### Chain and history scope

Use Ethereum mainnet (`chainId = 1`) as the first supported historical chain.

Reasons:
- Longest useful EVM history for `OnchainAge` experiments.
- Mature infrastructure and protocol history.
- Avoids multi-chain aggregation before the semantics are proven.

This is a coverage choice, not a claim that Ethereum activity represents all on-chain history. Every credential must declare chain/source coverage.

### Wallet ownership

Use EIP-4361 Sign-In with Ethereum (SIWE) formatted challenges.

The challenge must bind:
- wallet address
- chain ID
- domain/audience
- URI
- fresh nonce
- issued-at time
- short expiration time
- a human-readable statement explaining that the signature proves current wallet control only

Use `viem` as the initial EVM/SIWE library. Project code must still enforce its own stored-challenge checks, including exact-message matching and chain policy, rather than assuming a library call alone represents the complete security policy.

### History-provider abstraction

Create a project-owned `ChainHistoryProvider` interface. Reputation methodology must depend on this interface, never directly on a vendor response model.

First prototype adapter for `OnchainAge`: Etherscan API V2 normal-transactions-by-address endpoint.

Why Etherscan first:
- It returns normal transactions initiated by an address, including zero-value contract calls.
- This is a closer match to our first `OnchainAge` evidence definition than transfer-only history.
- It supports chain IDs through a common API surface, which gives a possible later migration path without changing reputation methodology.

Provider responses must be normalized into project-owned evidence types before entering the reputation engine.

### RPC strategy

Use standard Ethereum JSON-RPC behind an injected RPC URL/client. Do not hard-code one RPC vendor into domain logic.

A second data source will be added before production-like credential guarantees for critical claims.

### First lending protocol

Use Aave V3 Ethereum Core as the first lending-history research adapter.

Reasons:
- Mature deployment and historical activity.
- Clear lending/borrowing/liquidation semantics.
- Existing V3 documentation, contract architecture and indexing resources.
- More suitable for historical reputation work than starting with the newer Aave V4 architecture.

Aave V4 will be evaluated after the protocol-adapter contract is proven.

### Runtime/tooling

Prototype baseline:
- Node.js 24+
- TypeScript
- Vitest
- viem

Dependencies are pinned in the repository for reproducibility and updated deliberately.

## OnchainAge v0.1 evidence rule

For Ethereum mainnet, the first candidate evidence is the earliest successful, finalized normal transaction whose `from` address equals the currently controlled wallet.

Inbound transfers alone do not establish `OnchainAge`.

A qualifying transaction may include a zero-value contract call. Failed transactions do not qualify in v0.1.

The credential proves only:

> At issuance time, the holder demonstrated current control of a wallet that had qualifying activity at or before the threshold date in the declared covered source.

It does not prove continuous control by the same human.

## Alternatives considered

### Alchemy Transfers API as first history adapter

Useful and remains a candidate secondary provider, but normal transaction history is a cleaner initial fit for `OnchainAge` because the primitive is based on holder-initiated activity rather than transfer activity alone.

### Base as first chain

Lower-cost and relevant for current applications, but has much shorter history. It remains a strong candidate for the second chain.

### Aave V4 first

Current and strategically important, but too new for the first historical lending-reputation adapter. V3 gives us a better test bed for long-history semantics.

### Custom signing format

Rejected. EIP-4361 already provides a human-readable standardized structure with nonce/domain/time semantics.

## Risks

- Etherscan is still a vendor dependency for the first prototype.
- Ethereum-only coverage can create false expectations if wording is careless.
- EOA-only local signature verification would exclude smart accounts; the architecture must preserve a path to ERC-1271/ERC-6492 verification through a public client.
- Aave V3 protocol upgrades and market variants require explicit adapter/version coverage.
- Historical provider data can be incomplete or temporarily inconsistent.

## Controls

- Provider abstraction and normalized evidence model.
- Frozen fixtures for deterministic tests.
- Explicit source and block/time coverage in derived credentials.
- No wording such as “first ever on-chain activity” unless coverage becomes exhaustive.
- Cross-provider validation before production-like guarantees.
- Versioned Aave adapter and known-contract registry.

## Revisit if

- Etherscan data completeness is insufficient for defined evidence.
- Another provider offers materially better reproducibility or privacy characteristics.
- Smart-account adoption requires a different ownership-verification path.
- Ethereum-only scope blocks meaningful MVP testing.
- Aave V3 activity no longer provides a useful historical test set.
