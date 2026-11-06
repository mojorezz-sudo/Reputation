import type { JWK } from 'jose'
import type { SD_JWT_VC_TYPE } from '../../credentials/sd-jwt-vc.js'

export const OID4VP_STATIC_WALLET_AUDIENCE = 'https://self-issued.me/v2'
export const OID4VP_VC_QUERY_ID = 'onchain_age'
export const OID4VP_VC_FORMAT = 'jwt_vc_json' as const
export const OID4VP_VC_V1_CONTEXT = 'https://www.w3.org/2018/credentials/v1'
export const OID4VP_REQUEST_TYPE = 'oauth-authz-req+jwt'
export const OID4VP_ATTESTATION_TYPE = 'verifier-attestation+jwt'

export type OnchainAgeDcql = Readonly<{
  credentials: readonly [{
    id: typeof OID4VP_VC_QUERY_ID
    format: typeof OID4VP_VC_FORMAT
    require_cryptographic_holder_binding: true
    meta: Readonly<{ type_values: readonly [readonly [string, string]] }>
    claims: readonly [
      Readonly<{ path: readonly ['credentialSubject', 'primitive']; values: readonly ['OnchainAge'] }>,
      Readonly<{ path: readonly ['credentialSubject', 'chainId'] }>,
      Readonly<{ path: readonly ['credentialSubject', 'thresholdDate'] }>
    ]
  }]
}>

export type SdJwtOnchainAgeDcql = Readonly<{
  credentials: readonly [{
    id: typeof OID4VP_VC_QUERY_ID
    format: 'dc+sd-jwt'
    require_cryptographic_holder_binding: true
    meta: Readonly<{ vct_values: readonly [typeof SD_JWT_VC_TYPE] }>
    claims: readonly [{ path: readonly ['thresholdDate'] }]
  }]
}>

export type OpenId4VpRequestObject = Readonly<{
  client_id: string
  response_type: 'vp_token'
  response_mode: 'direct_post.jwt'
  response_uri: string
  nonce: string
  state: string
  dcql_query: OnchainAgeDcql | SdJwtOnchainAgeDcql
  client_metadata: Readonly<{
    vp_formats_supported: Readonly<{ jwt_vc_json: Readonly<{ alg_values: readonly ['ES256'] }> }> |
      Readonly<{ 'dc+sd-jwt': Readonly<{
        'sd-jwt_alg_values': readonly ['ES256']
        'kb-jwt_alg_values': readonly ['ES256']
      }> }>
    encrypted_response_enc_values_supported: readonly ['A128GCM']
    jwks: Readonly<{ keys: readonly JWK[] }>
  }>
}>

export type TrustedOnchainAgePolicy = Readonly<{
  issuer: string
  issuerKeyId: string
  issuerPublicKey: CryptoKey
  chainId: number
  methodologyVersion: string
  requiredThresholdDate: string
}>

export type OpenId4VpTransaction = Readonly<{
  state: string
  nonce: string
  clientId: string
  responseUri: string
  initiatedBySession: string
  issuedAt: number
  expiresAt: number
  policy: TrustedOnchainAgePolicy
  /** Immutable format selection saved with the transaction. */
  format?: 'jwt_vc_json' | 'dc+sd-jwt'
}>

export interface OpenId4VpTransactionStore {
  save(transaction: OpenId4VpTransaction): Promise<void>
  /** Atomically consumes a transaction by state after response decryption. */
  take(state: string): Promise<OpenId4VpTransaction | undefined>
}

export type OnchainAgeVpResult =
  | Readonly<{ status: 'satisfied'; chainId: number; thresholdDate: string }>
  | Readonly<{ status: 'not_satisfied'; reason: 'policy_not_met' }>
  | Readonly<{ status: 'unverifiable'; reason: string }>
