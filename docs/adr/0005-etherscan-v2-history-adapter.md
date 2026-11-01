# ADR 0005: Etherscan V2 as the first replaceable history adapter

- Status: Accepted for prototype
- Date: 2026-11-01

## Context

`OnchainAge v0.1` now has provider-neutral semantics. We need a first real source for Ethereum normal transaction history without allowing that source to define reputation meaning, finality, or negative-claim completeness.

Etherscan V2 exposes normal transactions by address with explicit `chainid`, `startblock`, `endblock`, `page`, `offset`, and `sort` parameters. The response includes transaction status fields such as `isError` and `txreceipt_status`.

The endpoint documents pagination but does not provide a cryptographic or protocol-level guarantee that exhausting API pages proves complete account history. That distinction matters because a negative reputation result must never depend only on absence of rows from one vendor.

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

The initial implementation uses generic Ethereum JSON-RPC with the `finalized` block tag through an injected client resolver. No RPC vendor is embedded in the reputation or history contracts.

### Pagination is necessary, not sufficient

A negative `OnchainAge` claim requires exhaustive history from genesis through the captured finalized block.

The Etherscan adapter therefore first:

1. requests pages sequentially;
2. uses a fixed block interval for all pages;
3. continues until a page contains fewer rows than the configured page size, or Etherscan returns its valid empty-result envelope;
4. throws if a configured safety page limit is reached while pages are still full.

Reaching the end of pagination is **not by itself enough** to set `coverage.complete = true`.

### Independent EOA completeness check

For EOA-style normal transaction history, the adapter may receive an independent `AccountTransactionCountProvider`.

At the same captured finalized block, the provider queries Ethereum JSON-RPC `eth_getTransactionCount(address, blockNumber)`. For an EOA, this transaction count/nonce represents the number of outbound account transactions included up to that block.

The adapter compares:

- number of normalized outbound normal transactions observed from Etherscan from genesis through the finalized block; and
- independent account transaction count at that exact block.

Only an exact match allows `coverage.complete = true`.

If no independent count provider is configured, or the counts do not match, the adapter returns the history with `coverage.complete = false` rather than pretending the absence of additional rows is conclusive.

This preserves useful positive evidence: an old qualifying transaction can still prove `OnchainAge = satisfied`. But a missing old transaction cannot become `not_satisfied`; the reputation evaluator will return `unverifiable` when completeness is not established.

If the configured transaction-count provider itself fails, the adapter propagates the operational failure rather than silently degrading it into a trustworthy negative conclusion.

### Smart-account limitation

The EOA nonce invariant is not a universal completeness proof for contract/smart accounts. Contract accounts may have transaction activity without an EOA-style outbound nonce history matching Etherscan rows.

Therefore a mismatch is not automatically treated as corruption; it makes coverage incomplete. Smart-account negative claims remain `unverifiable` until a wallet-class-specific completeness mechanism is designed.

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

The Etherscan endpoint can include transactions where the queried address is the receiver. Since `ChainHistoryProvider.getOutboundTransactions` promises outbound history, valid inbound rows are ignored rather than passed to the reputation engine.

Contract-creation rows with an empty `to` field normalize to `to = null`.

A zero-value outbound call is preserved; zero value is not evidence of spam by itself and `OnchainAge v0.1` explicitly permits successful holder-authorized contract calls.

## Security properties

- Vendor response shape does not leak into reputation methodology.
- Provider failure cannot silently become `not_satisfied`.
- Pagination exhaustion alone cannot silently become complete coverage.
- Negative EOA claims require an independent account-count invariant at the same frozen block.
- Finality is controlled by an independent JSON-RPC boundary.
- API keys are supplied at runtime and are redacted from both network and provider-error paths.
- Query block range is frozen before pagination to avoid a moving-chain-head race.

## Trade-offs

- Etherscan remains an availability and data-quality dependency for this adapter.
- Sequential pagination is slower than aggressive concurrency but easier to rate-limit and reason about.
- Very active wallets may be expensive to scan from genesis.
- Independent RPC adds another dependency, but it deliberately reduces trust in any one history vendor.
- `OnchainAge v0.1` covers normal EVM transactions only and does not yet model account-abstraction user operations as independent reputation activity.
- Smart accounts cannot yet obtain strong negative-history conclusions from the EOA completeness invariant.

## Revisit if

- Etherscan's pagination or data guarantees prove insufficient;
- historical scans become too slow or expensive;
- a second provider exposes materially better reproducibility;
- smart-account activity requires a broader activity source;
- production requires cross-provider reconciliation for every issuance.
