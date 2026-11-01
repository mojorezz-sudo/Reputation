# ADR 0005: Etherscan V2 as the first replaceable history adapter

- Status: Accepted for prototype
- Date: 2026-11-01

## Context

`OnchainAge v0.1` now has provider-neutral semantics. We need a first real source for Ethereum normal transaction history without allowing that source to define reputation meaning, finality, or negative-claim completeness.

Etherscan V2 exposes normal transactions by address with explicit `chainid`, `startblock`, `endblock`, `page`, `offset`, and `sort` parameters. The response includes transaction status fields such as `isError` and `txreceipt_status`.

## Decision

Implement Etherscan V2 behind the existing `ChainHistoryProvider` interface.

The reputation engine must never consume Etherscan response objects directly.

### Independent finality boundary

Etherscan does not decide our finalized history boundary.

The adapter receives a separate `FinalizedBlockProvider` and first captures a finalized block number for the requested chain. Every Etherscan page is then queried with:

- `startblock = 0`
- `endblock = captured finalized block`
- ascending sort

All normalized transactions are therefore constrained to the captured finalized range. The adapter still validates that no returned row lies beyond that boundary.

A future `FinalizedBlockProvider` may use an Ethereum JSON-RPC `finalized` block tag through any compatible RPC provider. This keeps finality independent from Etherscan and independent from one RPC vendor.

### Pagination and completeness

A negative `OnchainAge` claim requires exhaustive history from genesis through the captured finalized block.

Therefore the adapter:

1. requests pages sequentially;
2. uses a fixed block interval for all pages;
3. continues until a page contains fewer rows than the configured page size, or Etherscan returns its valid empty-result envelope;
4. marks coverage `complete = true` only after that exhaustion condition;
5. throws rather than returning `complete = true` if a configured safety page limit is reached while pages are still full.

This avoids treating truncated pagination as absence of history.

### Rate limiting

Etherscan's current Free tier is documented at 3 calls/second. The prototype adapter therefore uses a conservative configurable inter-request delay by default. Paid/higher-rate deployments may override it.

Rate-limit responses remain errors; they must never be converted into empty history.

### Empty result versus error

Etherscan may return an empty-but-valid transaction query using status `0` with a “No transactions found” message and an empty result array. The adapter recognizes only that narrow form as empty history.

Status `0` / `NOTOK`, string errors, HTTP errors, malformed payloads, and rate-limit failures are provider errors and do not become negative reputation claims.

### Normalization

The adapter validates provider data before constructing project-owned normalized transactions:

- decimal block number, timestamp, transaction index, and wei value
- transaction hash shape
- EVM addresses
- hex calldata
- transaction execution status
- block number within the captured finalized boundary

The Etherscan endpoint can include transactions where the queried address is the receiver. Since `ChainHistoryProvider.getOutboundTransactions` promises outbound history, valid inbound rows are ignored after validation rather than passed to the reputation engine.

Contract-creation rows with an empty `to` field normalize to `to = null`.

A zero-value outbound call is preserved; zero value is not evidence of spam by itself and `OnchainAge v0.1` explicitly permits successful holder-authorized contract calls.

## Security properties

- Vendor response shape does not leak into reputation methodology.
- Provider failure cannot silently become `not_satisfied`.
- Pagination truncation cannot silently become complete coverage.
- Finality is controlled by an independent boundary.
- API keys are supplied at runtime and must never be committed or included in adapter error messages.
- Query block range is frozen before pagination to avoid a moving-chain-head race.

## Trade-offs

- Etherscan remains an availability and data-quality dependency for this adapter.
- Sequential pagination is slower than aggressive concurrency but easier to rate-limit and reason about.
- Very active wallets may be expensive to scan from genesis.
- `OnchainAge v0.1` covers normal EVM transactions only and does not yet model account-abstraction user operations as independent reputation activity.

## Revisit if

- Etherscan's pagination or data guarantees prove insufficient;
- historical scans become too slow or expensive;
- a second provider exposes materially better reproducibility;
- smart-account activity requires a broader activity source;
- production requires cross-provider reconciliation for every issuance.
