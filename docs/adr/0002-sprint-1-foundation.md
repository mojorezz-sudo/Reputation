# ADR-0002: Sprint 1 foundation — Ethereum, SIWE, provider abstraction

Status: Accepted for Sprint 1
Date: 2026-11-01

## Context

Sprint 1 needs one narrow, reproducible path from wallet control to an `OnchainAge` credential without locking the reputation engine to one RPC/indexing vendor or prematurely committing to a ZK stack.

## Decisions

### 1. First chain: Ethereum mainnet

Ethereum mainnet is the first historical source for `OnchainAge` and the first protocol-adapter research scope.

Why:
- longest and richest EVM account history;
- mature wallet/signature standards;
- mature lending history;
- future EVM chains can reuse most abstractions.

This is an implementation starting point, not a product claim that reputation is Ethereum-only.

### 2. Wallet-control proof: ERC-4361 Sign-In with Ethereum (SIWE)

Use SIWE semantics rather than inventing a custom signing payload.

The challenge must bind at minimum:
- domain/origin;
- address;
- URI;
- chain ID;
- cryptographically strong one-time nonce;
- issued-at;
- short expiration;
- request identifier where useful.

EOAs use ERC-191 verification. Contract accounts must have an explicit ERC-1271 verification path resolved against the declared chain.

A consumed nonce cannot be reused. Signature validity proves current control only; it does not prove continuous historical ownership by the same human.

### 3. Data access: internal interfaces, provider adapters

Core reputation logic MUST NOT call a vendor SDK directly.

Boundary:

`RpcProvider -> normalized chain observations -> reputation primitive`

The first implementation may use any standards-compatible Ethereum JSON-RPC endpoint supplied by configuration. Provider-specific acceleration/indexing may be added behind adapters later.

No provider API key, hostname or proprietary response shape may appear inside reputation primitive logic.

### 4. Historical reproducibility

Every computed reputation result must record enough provenance to reproduce the result against a frozen snapshot where practical:
- chain ID;
- methodology version;
- evaluated block number/hash or bounded block range;
- adapter version;
- relevant protocol version/addresses when protocol-specific;
- fixture/source identifier in tests.

### 5. First lending protocol candidate: Aave

Aave remains the first lending-adapter candidate because it has mature public deployments and well-defined smart-contract behavior. It is NOT part of the first wallet-ownership implementation and remains subject to a dedicated adapter ADR before protocol-specific code lands.

## Consequences

### Advantages
- avoids custom authentication cryptography;
- keeps provider replacement possible;
- gives us a long historical dataset;
- makes semantic and data provenance explicit from the first primitive.

### Risks
- Ethereum RPC history can be expensive/slow depending on provider;
- smart-contract wallets add ERC-1271 state-dependent verification complexity;
- earliest transaction/activity does not prove continuous ownership;
- a single-chain MVP can underrepresent a user's real cross-chain history.

## Revisit conditions

Revisit this ADR if:
- historical Ethereum retrieval becomes impractical for the MVP;
- a provider abstraction cannot preserve required provenance;
- multi-chain evidence is required to validate the product thesis;
- wallet support shows SIWE interoperability gaps that materially harm the MVP.
