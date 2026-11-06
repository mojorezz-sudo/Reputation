import type { Address, Hex } from 'viem'

export type OwnershipChallenge = Readonly<{
  address: Address
  chainId: number
  domain: string
  uri: string
  nonce: string
  message: string
  issuedAt: Date
  expiresAt: Date
  /**
   * Opaque server-side session/profile binding. This value is intentionally
   * not embedded in the public SIWE message or verifier-facing output.
   */
  holderSessionId: string
}>

export interface OwnershipChallengeStore {
  save(challenge: OwnershipChallenge): Promise<void>

  /**
   * Atomically consumes the challenge only when it belongs to the expected
   * holder session. A session mismatch must be indistinguishable from a
   * missing/consumed nonce to callers.
   */
  take(
    nonce: string,
    holderSessionId: string,
  ): Promise<OwnershipChallenge | undefined>
}

export interface MessageSignatureVerifier {
  verify(input: {
    address: Address
    chainId: number
    message: string
    signature: Hex
  }): Promise<boolean>
}

export type OwnershipVerificationFailureReason =
  | 'malformed_message'
  | 'challenge_not_found_or_consumed'
  | 'challenge_expired'
  | 'challenge_not_yet_valid'
  | 'message_mismatch'
  | 'chain_mismatch'
  | 'siwe_validation_failed'
  | 'invalid_signature'

export type OwnershipVerificationResult =
  | Readonly<{
      ok: true
      address: Address
      chainId: number
      verifiedAt: Date
    }>
  | Readonly<{
      ok: false
      reason: OwnershipVerificationFailureReason
    }>
