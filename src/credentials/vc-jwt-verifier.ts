import {
  decodeJwt,
  decodeProtectedHeader,
  jwtVerify,
  type JWK,
  type JWTPayload,
} from 'jose'

import { normalizePublicP256Jwk } from './jwk.js'
import {
  ONCHAIN_AGE_CREDENTIAL_SCHEMA_VERSION,
  ONCHAIN_AGE_CREDENTIAL_TYPE,
  REPUTATION_VC_CONTEXT,
  VC_V2_CONTEXT,
  type OnchainAgeCredential,
  type OnchainAgeCredentialSubject,
} from './types.js'

export const MAX_VC_JWT_LENGTH = 64_000

export interface IssuerKeyResolver {
  resolve(input: {
    issuer: string
    kid: string
    alg: 'ES256'
  }): Promise<CryptoKey>
}

export class CredentialVerificationError extends Error {
  override readonly name = 'CredentialVerificationError'

  constructor(
    readonly code:
      | 'malformed_credential'
      | 'unsupported_header'
      | 'issuer_key_unavailable'
      | 'invalid_signature_or_time'
      | 'invalid_credential_model'
      | 'invalid_holder_binding',
    message: string,
  ) {
    super(message)
  }
}

export type VerifiedOnchainAgeCredential = Readonly<{
  token: string
  model: OnchainAgeCredential
  issuer: string
  kid: string
  issuedAt: Date
  expiresAt: Date
  holderPublicJwk: JWK
  holderPublicKey: CryptoKey
}>

export class OnchainAgeVcJwtVerifier {
  readonly #issuerKeyResolver: IssuerKeyResolver

  constructor(issuerKeyResolver: IssuerKeyResolver) {
    this.#issuerKeyResolver = issuerKeyResolver
  }

  async verify(
    token: string,
    now = new Date(),
  ): Promise<VerifiedOnchainAgeCredential> {
    if (token.length === 0 || token.length > MAX_VC_JWT_LENGTH) {
      throw new CredentialVerificationError(
        'malformed_credential',
        'credential size is invalid',
      )
    }
    assertValidDate(now, 'verification time')

    let header: ReturnType<typeof decodeProtectedHeader>
    let unverified: JWTPayload
    try {
      header = decodeProtectedHeader(token)
      unverified = decodeJwt(token)
    } catch {
      throw new CredentialVerificationError(
        'malformed_credential',
        'credential is not a valid compact JWT',
      )
    }

    if (
      header.alg !== 'ES256' ||
      header.typ !== 'vc+jwt' ||
      header.cty !== 'vc' ||
      typeof header.kid !== 'string' ||
      header.kid.length === 0
    ) {
      throw new CredentialVerificationError(
        'unsupported_header',
        'credential JOSE header is outside the supported profile',
      )
    }

    const issuer = unverified.iss
    if (typeof issuer !== 'string' || !isAbsoluteHttpUrl(issuer)) {
      throw new CredentialVerificationError(
        'invalid_credential_model',
        'credential JWT issuer is missing or invalid',
      )
    }

    let issuerKey: CryptoKey
    try {
      issuerKey = await this.#issuerKeyResolver.resolve({
        issuer,
        kid: header.kid,
        alg: 'ES256',
      })
    } catch {
      throw new CredentialVerificationError(
        'issuer_key_unavailable',
        'issuer verification key could not be resolved',
      )
    }

    let verified: JWTPayload
    try {
      const result = await jwtVerify(token, issuerKey, {
        issuer,
        algorithms: ['ES256'],
        clockTimestamp: Math.floor(now.getTime() / 1_000),
      })
      verified = result.payload
    } catch {
      throw new CredentialVerificationError(
        'invalid_signature_or_time',
        'credential signature or JWT validity failed',
      )
    }

    const parsed = parseCredentialPayload(verified, issuer)

    let holder
    try {
      holder = await normalizePublicP256Jwk(parsed.holderPublicJwk)
    } catch {
      throw new CredentialVerificationError(
        'invalid_holder_binding',
        'credential holder proof-of-possession key is invalid',
      )
    }

    if (now < parsed.validFrom || now >= parsed.validUntil) {
      throw new CredentialVerificationError(
        'invalid_signature_or_time',
        'credential VC validity window is not current',
      )
    }

    return {
      token,
      model: parsed.model,
      issuer,
      kid: header.kid,
      issuedAt: parsed.issuedAt,
      expiresAt: parsed.validUntil,
      holderPublicJwk: holder.jwk,
      holderPublicKey: holder.key,
    }
  }
}

function parseCredentialPayload(
  payload: JWTPayload,
  expectedIssuer: string,
): {
  model: OnchainAgeCredential
  holderPublicJwk: JWK
  issuedAt: Date
  validFrom: Date
  validUntil: Date
} {
  assertOnlyKeys(payload, [
    '@context',
    'type',
    'issuer',
    'validFrom',
    'validUntil',
    'credentialSubject',
    'cnf',
    'iss',
    'iat',
    'exp',
  ])

  if (payload.issuer !== expectedIssuer) {
    invalidModel('credential issuer does not match JWT iss')
  }
  if (payload.vc !== undefined) {
    invalidModel('legacy nested vc claim is not supported')
  }

  assertContext(payload['@context'])
  assertCredentialType(payload.type)

  const validFrom = parseDateString(payload.validFrom, 'validFrom')
  const validUntil = parseDateString(payload.validUntil, 'validUntil')
  if (validUntil <= validFrom) {
    invalidModel('validUntil must be after validFrom')
  }

  if (
    typeof payload.iat !== 'number' ||
    !Number.isSafeInteger(payload.iat) ||
    typeof payload.exp !== 'number' ||
    !Number.isSafeInteger(payload.exp)
  ) {
    invalidModel('credential JWT iat/exp claims are invalid')
  }

  if (
    Math.abs(validFrom.getTime() - payload.iat * 1_000) >= 1_000 ||
    Math.abs(validUntil.getTime() - payload.exp * 1_000) >= 1_000
  ) {
    invalidModel('VC validity and JWT validity claims do not agree')
  }

  const credentialSubject = parseCredentialSubject(payload.credentialSubject)
  const holderPublicJwk = parseHolderJwk(payload.cnf)

  return {
    model: {
      '@context': [VC_V2_CONTEXT, REPUTATION_VC_CONTEXT],
      type: ['VerifiableCredential', ONCHAIN_AGE_CREDENTIAL_TYPE],
      issuer: expectedIssuer,
      validFrom: validFrom.toISOString(),
      validUntil: validUntil.toISOString(),
      credentialSubject,
    },
    holderPublicJwk,
    issuedAt: new Date(payload.iat * 1_000),
    validFrom,
    validUntil,
  }
}

function parseCredentialSubject(value: unknown): OnchainAgeCredentialSubject {
  if (!isRecord(value)) invalidModel('credentialSubject must be an object')
  assertOnlyKeys(value, [
    'primitive',
    'chainId',
    'thresholdDate',
    'methodologyVersion',
    'schemaVersion',
    'sourceCoverage',
  ])

  if (value.primitive !== 'OnchainAge') {
    invalidModel('credentialSubject primitive is invalid')
  }
  if (!Number.isInteger(value.chainId) || Number(value.chainId) <= 0) {
    invalidModel('credentialSubject chainId is invalid')
  }
  const thresholdDate = parseDateString(value.thresholdDate, 'thresholdDate')
  if (
    typeof value.methodologyVersion !== 'string' ||
    value.methodologyVersion.length === 0
  ) {
    invalidModel('methodologyVersion is invalid')
  }
  if (value.schemaVersion !== ONCHAIN_AGE_CREDENTIAL_SCHEMA_VERSION) {
    invalidModel('schemaVersion is unsupported')
  }

  if (!isRecord(value.sourceCoverage)) {
    invalidModel('sourceCoverage must be an object')
  }
  assertOnlyKeys(value.sourceCoverage, [
    'providerId',
    'fromBlock',
    'throughBlock',
    'complete',
  ])

  if (
    typeof value.sourceCoverage.providerId !== 'string' ||
    value.sourceCoverage.providerId.length === 0
  ) {
    invalidModel('sourceCoverage providerId is invalid')
  }
  const fromBlock = parseDecimalBigInt(
    value.sourceCoverage.fromBlock,
    'sourceCoverage.fromBlock',
  )
  const throughBlock = parseDecimalBigInt(
    value.sourceCoverage.throughBlock,
    'sourceCoverage.throughBlock',
  )
  if (fromBlock > throughBlock) {
    invalidModel('sourceCoverage block interval is invalid')
  }
  if (typeof value.sourceCoverage.complete !== 'boolean') {
    invalidModel('sourceCoverage complete flag is invalid')
  }

  return {
    primitive: 'OnchainAge',
    chainId: Number(value.chainId),
    thresholdDate: thresholdDate.toISOString(),
    methodologyVersion: value.methodologyVersion,
    schemaVersion: ONCHAIN_AGE_CREDENTIAL_SCHEMA_VERSION,
    sourceCoverage: {
      providerId: value.sourceCoverage.providerId,
      fromBlock: fromBlock.toString(),
      throughBlock: throughBlock.toString(),
      complete: value.sourceCoverage.complete,
    },
  }
}

function parseHolderJwk(value: unknown): JWK {
  if (!isRecord(value)) invalidModel('cnf must be an object')
  assertOnlyKeys(value, ['jwk'])
  if (!isRecord(value.jwk)) invalidModel('cnf.jwk must be an object')
  return { ...value.jwk } as JWK
}

function assertContext(value: unknown): void {
  if (!Array.isArray(value) || value.length !== 2) {
    invalidModel('@context is outside the supported credential profile')
  }
  if (value[0] !== VC_V2_CONTEXT || !isRecord(value[1])) {
    invalidModel('@context is outside the supported credential profile')
  }

  const expected = REPUTATION_VC_CONTEXT as Record<string, string>
  assertOnlyKeys(value[1], Object.keys(expected))
  for (const [key, iri] of Object.entries(expected)) {
    if (value[1][key] !== iri) {
      invalidModel('@context reputation term mapping is invalid')
    }
  }
}

function assertCredentialType(value: unknown): void {
  if (
    !Array.isArray(value) ||
    value.length !== 2 ||
    value[0] !== 'VerifiableCredential' ||
    value[1] !== ONCHAIN_AGE_CREDENTIAL_TYPE
  ) {
    invalidModel('credential type is outside the supported profile')
  }
}

function parseDateString(value: unknown, field: string): Date {
  if (typeof value !== 'string') invalidModel(`${field} must be a string`)
  const date = new Date(value)
  if (Number.isNaN(date.getTime()) || date.toISOString() !== value) {
    invalidModel(`${field} must be a canonical ISO timestamp`)
  }
  return date
}

function parseDecimalBigInt(value: unknown, field: string): bigint {
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(value)) {
    invalidModel(`${field} must be a canonical unsigned decimal integer`)
  }
  return BigInt(value)
}

function assertOnlyKeys(
  value: Record<string, unknown> | JWTPayload,
  allowedKeys: readonly string[],
): void {
  const allowed = new Set(allowedKeys)
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      invalidModel(`unexpected credential claim: ${key}`)
    }
  }
}

function assertValidDate(value: Date, field: string): void {
  if (Number.isNaN(value.getTime())) {
    throw new CredentialVerificationError(
      'malformed_credential',
      `${field} must be a valid Date`,
    )
  }
}

function isAbsoluteHttpUrl(value: string): boolean {
  try {
    const url = new URL(value)
    return url.protocol === 'https:' || url.protocol === 'http:'
  } catch {
    return false
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function invalidModel(message: string): never {
  throw new CredentialVerificationError('invalid_credential_model', message)
}
