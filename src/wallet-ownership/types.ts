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
}>

export interface OwnershipChallengeStore {
  save(challenge: OwnershipChallenge): Promise<void>
  take(nonce: string): Promise<OwnershipChallenge | undefined>
}

export interface MessageSignatureVerifier {
  verify(input: {
    address: Address
    message: string
    signature: Hex
  }): Promise<boolean>
}

export type OwnershipVerificationFailureReason =
  | 'malformed_message'
  | 'challenge_not_found_or_consumed'
  | 'challenge_expired'
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
