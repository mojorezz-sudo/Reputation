# Wallet Ownership v0.1

Status: Draft for implementation
Baseline: ERC-4361 Sign-In with Ethereum

## Goal

Prove current control of an Ethereum account for a short-lived reputation session without collecting private keys and without treating current control as proof of historical human ownership.

## Challenge lifecycle

1. Server creates a cryptographically strong one-time nonce.
2. Server/client constructs a SIWE-conformant human-readable message.
3. Wallet signs after displaying the request.
4. Verifier parses the message and checks all expected fields before signature verification.
5. Signature is verified for the declared account type and chain context.
6. Nonce is atomically marked consumed.
7. A short-lived internal holder session is established.

## Required validation

Reject unless all applicable checks pass:
- SIWE syntax/version is supported;
- domain/scheme matches trusted request origin policy;
- URI matches the expected resource;
- address equals the intended subject;
- chain ID is supported;
- nonce exists, has sufficient entropy, is unconsumed and belongs to this challenge;
- issued-at is within allowed clock skew;
- expiration has not passed;
- not-before, if present, has passed;
- request ID, if used, matches expected request;
- signature is valid;
- challenge has not already been consumed.

## Signature paths

### EOA
Verify the ERC-191 personal signature over the exact SIWE message.

### Contract account
Use ERC-1271 against the declared chain context. Because contract-signature validity can depend on chain state, the verification result must retain the evaluated block/context where practical and sessions may require invalidation when relevant account state changes.

## Replay protection

Nonce consumption must be atomic. A second submission of the same challenge fails even if the signature itself remains cryptographically valid.

Suggested challenge TTL for MVP: 5 minutes. This is an application policy and may change after UX/security testing.

## Privacy

Do not use wallet address as the default identifier exposed to third-party verifiers. Wallet addresses belong to the private holder-linking layer unless a verifier use case explicitly requires disclosure and the holder consents.

Do not log full signed messages/signatures indefinitely. Retention policy must be defined before production.

## Security semantics

A successful result means:

`CurrentControl(address, time, audience) = true`

It does NOT mean:

`SameHumanControlledAddressForEntireHistory = true`

This distinction must survive into downstream credential wording and APIs.

## Required tests

- valid EOA signature succeeds;
- wrong signer fails;
- altered message fails;
- wrong domain fails;
- wrong URI fails;
- wrong chain ID fails;
- unknown nonce fails;
- expired challenge fails;
- future not-before fails;
- replay fails;
- concurrent double-submit results in at most one success;
- malformed SIWE message fails closed;
- ERC-1271 path is either correctly supported or explicitly returns unsupported, never silently treated as EOA.
