import type { JWK } from 'jose'

export const VC_V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2' as const
export const ONCHAIN_AGE_CREDENTIAL_SCHEMA_VERSION =
  'onchain-age-credential/0.1.0' as const
export const ONCHAIN_AGE_CREDENTIAL_TYPE =
  'urn:reputation:type:OnchainAgeCredential' as const

export const REPUTATION_VC_CONTEXT = Object.freeze({
  primitive: 'urn:reputation:claim:primitive',
  chainId: 'urn:reputation:claim:chainId',
  thresholdDate: 'urn:reputation:claim:thresholdDate',
  methodologyVersion: 'urn:reputation:claim:methodologyVersion',
  schemaVersion: 'urn:reputation:claim:schemaVersion',
  sourceCoverage: 'urn:reputation:claim:sourceCoverage',
  providerId: 'urn:reputation:claim:providerId',
  fromBlock: 'urn:reputation:claim:fromBlock',
  throughBlock: 'urn:reputation:claim:throughBlock',
  complete: 'urn:reputation:claim:complete',
})

export type OnchainAgeCredentialSubject = Readonly<{
  primitive: 'OnchainAge'
  chainId: number
  thresholdDate: string
  methodologyVersion: string
  schemaVersion: typeof ONCHAIN_AGE_CREDENTIAL_SCHEMA_VERSION
  sourceCoverage: Readonly<{
    providerId: string
    fromBlock: string
    throughBlock: string
    complete: boolean
  }>
}>

export type OnchainAgeCredential = Readonly<{
  '@context': readonly [
    typeof VC_V2_CONTEXT,
    typeof REPUTATION_VC_CONTEXT,
  ]
  type: readonly ['VerifiableCredential', typeof ONCHAIN_AGE_CREDENTIAL_TYPE]
  issuer: string
  /** Unique signed credential identifier for issuer-side revocation. */
  id?: string
  validFrom: string
  validUntil: string
  credentialSubject: OnchainAgeCredentialSubject
}>

export type SecuredCredential = Readonly<{
  mediaType: 'application/vc+jwt'
  value: string
  validUntil: Date
}>

export interface CredentialSigner<TCredential> {
  readonly mediaType: 'application/vc+jwt'

  sign(input: {
    credential: TCredential
    holderPublicJwk: JWK
    issuedAt: Date
    signatureExpiresAt: Date
  }): Promise<SecuredCredential>
}
