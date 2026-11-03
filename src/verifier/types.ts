import type { CryptoKey, JWK } from 'jose'

/**
 * A verifier's policies and trust roots come from trusted server configuration,
 * never from a request supplied by a wallet or third party.
 */
export type OnchainAgeVerifierPolicy = Readonly<{
  issuer: string
  issuerKeyId: string
  issuerPublicKey: CryptoKey
  chainId: number
  methodologyVersion: string
  /** A credential with an equal or EARLIER threshold is sufficiently old. */
  requiredThresholdDate: string
}>

export type PresentationRequest = Readonly<{
  nonce: string
  audience: string
  issuedAt: string
  expiresAt: string
  policy: Readonly<{
    primitive: 'OnchainAge'
    chainId: number
    methodologyVersion: string
    requiredThresholdDate: string
  }>
}>

export interface PresentationChallengeStore {
  save(request: PresentationRequest): Promise<void>
  /** Must atomically remove only an exact nonce + audience match. */
  take(nonce: string, audience: string): Promise<PresentationRequest | undefined>
}

export type HolderPresentation = Readonly<{
  credentialJwt: string
  holderProofJwt: string
  nonce: string
}>

export type CredentialStatus = 'valid' | 'revoked' | 'unknown'

export interface CredentialStatusChecker {
  /** Must fail closed if issuer/status data cannot be trusted or reached. */
  check(input: { credentialJwt: string; issuer: string; issuerKeyId: string }): Promise<CredentialStatus>
}

export type VerifierFailureReason =
  | 'challenge_not_found_or_consumed'
  | 'challenge_expired'
  | 'invalid_credential'
  | 'invalid_holder_proof'
  | 'invalid_policy'
  | 'credential_revoked'
  | 'credential_status_unknown'
  | 'policy_not_met'

export type VerificationResult =
  | Readonly<{
      status: 'satisfied'
      methodologyVersion: string
      chainId: number
      thresholdDate: string
    }>
  | Readonly<{
      status: 'not_satisfied'
      reason: 'policy_not_met'
    }>
  | Readonly<{
      status: 'unverifiable'
      reason: Exclude<VerifierFailureReason, 'policy_not_met'>
    }>

/** Minimal signed claim shape, checked explicitly after verifying signature. */
export type VerifiedOnchainAgeClaim = Readonly<{
  issuer: string
  validFrom: string
  validUntil: string
  subject: Readonly<{
    primitive: 'OnchainAge'
    chainId: number
    thresholdDate: string
    methodologyVersion: string
    schemaVersion: string
  }>
  holderPublicJwk: JWK
}>
