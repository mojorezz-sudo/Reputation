import { verifyMessage, type Address, type Hex } from 'viem'
import { parseSiweMessage, validateSiweMessage } from 'viem/siwe'

import type {
  MessageSignatureVerifier,
  OwnershipChallengeStore,
  OwnershipVerificationResult,
} from './types.js'

export const MAX_CHALLENGE_CLOCK_SKEW_MS = 30_000

/**
 * Production can inject a public client bound to the declared chain to
 * support ERC-1271/6492 (depending on the client's capabilities). The caller
 * must configure the client against a trusted RPC and the expected chain.
 */
export function createChainAwareMessageSignatureVerifier(
  chainId: number,
  client: { verifyMessage(args: { address: Address; message: string; signature: Hex }): Promise<boolean> },
): MessageSignatureVerifier {
  return {
    async verify(input) {
      if (input.chainId !== chainId) return false
      return client.verifyMessage({ address: input.address, message: input.message, signature: input.signature })
    },
  }
}

/** EOA-only fallback. Do not use for smart-contract account sessions. */
export const eoaMessageSignatureVerifier: MessageSignatureVerifier = {
  async verify({ address, message, signature }) {
    return verifyMessage({ address, message, signature })
  },
}

export type VerifyOwnershipProofInput = Readonly<{
  message: string
  signature: Hex
  /** Opaque server-side holder/session reference expected for this challenge. */
  holderSessionId: string
  now?: Date
}>

export async function verifyOwnershipProof(
  input: VerifyOwnershipProofInput,
  store: OwnershipChallengeStore,
  signatureVerifier: MessageSignatureVerifier = eoaMessageSignatureVerifier,
): Promise<OwnershipVerificationResult> {
  const now = input.now ?? new Date()
  if (Number.isNaN(now.getTime()) || input.holderSessionId.trim().length === 0) {
    return { ok: false, reason: 'malformed_message' }
  }

  let parsed: ReturnType<typeof parseSiweMessage>
  try {
    parsed = parseSiweMessage(input.message)
  } catch {
    return { ok: false, reason: 'malformed_message' }
  }

  if (!parsed.nonce) {
    return { ok: false, reason: 'malformed_message' }
  }

  // The store atomically enforces both session binding and single-use semantics.
  // A different session receives the same public failure as a missing nonce and
  // does not consume the legitimate holder's challenge.
  const challenge = await store.take(parsed.nonce, input.holderSessionId)
  if (!challenge) {
    return { ok: false, reason: 'challenge_not_found_or_consumed' }
  }

  if (now.getTime() + MAX_CHALLENGE_CLOCK_SKEW_MS < challenge.issuedAt.getTime()) {
    return { ok: false, reason: 'challenge_not_yet_valid' }
  }

  if (now >= challenge.expiresAt) {
    return { ok: false, reason: 'challenge_expired' }
  }

  // Do not reconstruct what the holder "probably" signed. We require the
  // exact server-issued bytes so domain, URI, statement, times and nonce are
  // all bound to the stored challenge.
  if (input.message !== challenge.message) {
    return { ok: false, reason: 'message_mismatch' }
  }

  if (parsed.chainId !== challenge.chainId) {
    return { ok: false, reason: 'chain_mismatch' }
  }

  const siweValid = validateSiweMessage({
    message: parsed,
    address: challenge.address,
    domain: challenge.domain,
    nonce: challenge.nonce,
    time: now,
  })

  if (!siweValid) {
    return { ok: false, reason: 'siwe_validation_failed' }
  }

  let signatureValid = false
  try {
    signatureValid = await signatureVerifier.verify({
      address: challenge.address,
      chainId: challenge.chainId,
      message: input.message,
      signature: input.signature,
    })
  } catch {
    signatureValid = false
  }

  if (!signatureValid) {
    return { ok: false, reason: 'invalid_signature' }
  }

  return {
    ok: true,
    address: challenge.address,
    chainId: challenge.chainId,
    verifiedAt: new Date(now),
  }
}
