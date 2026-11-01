import { verifyMessage, type Hex } from 'viem'
import { parseSiweMessage, validateSiweMessage } from 'viem/siwe'

import type {
  MessageSignatureVerifier,
  OwnershipChallengeStore,
  OwnershipVerificationResult,
} from './types.js'

export const eoaMessageSignatureVerifier: MessageSignatureVerifier = {
  async verify({ address, message, signature }) {
    return verifyMessage({ address, message, signature })
  },
}

export type VerifyOwnershipProofInput = Readonly<{
  message: string
  signature: Hex
  now?: Date
}>

export async function verifyOwnershipProof(
  input: VerifyOwnershipProofInput,
  store: OwnershipChallengeStore,
  signatureVerifier: MessageSignatureVerifier = eoaMessageSignatureVerifier,
): Promise<OwnershipVerificationResult> {
  const now = input.now ?? new Date()
  if (Number.isNaN(now.getTime())) {
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

  // Single-use semantics are enforced before cryptographic verification.
  // An invalid attempt burns the challenge; the holder requests a new one.
  const challenge = await store.take(parsed.nonce)
  if (!challenge) {
    return { ok: false, reason: 'challenge_not_found_or_consumed' }
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
