import {
  base64url,
  decodeJwt,
  decodeProtectedHeader,
  importJWK,
  jwtVerify,
  SignJWT,
  type JWK,
  type JWTPayload,
} from 'jose'
import type { CredentialStatusChecker } from '../verifier/types.js'
import type { IssuedCredentialRegistry } from '../issuance/secure-session.js'

export const SD_JWT_VC_DRAFT_VERSION = 'draft-ietf-oauth-sd-jwt-vc-25' as const
export const SD_JWT_VC_TYPE = 'https://reputation.example/vct/onchain-age-v0.1' as const
export const SD_JWT_CREDENTIAL_MEDIA_TYPE = 'application/dc+sd-jwt' as const

const MAX_TOKEN_SIZE = 32_768
const MAX_PROOF_SECONDS = 120
const CLOCK_SKEW_SECONDS = 30

function record(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v)
}
function holderJwk(v: unknown): v is JWK {
  return record(v) && v.kty === 'EC' && v.crv === 'P-256' &&
    typeof v.x === 'string' && typeof v.y === 'string' &&
    v.d === undefined && v.k === undefined
}
function iso(value: unknown): value is string {
  if (typeof value !== 'string') return false
  const d = new Date(value)
  return Number.isFinite(d.getTime()) && d.toISOString() === value
}
async function sha256(value: string): Promise<string> {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return base64url.encode(new Uint8Array(bytes))
}
function randomSalt(): string {
  return base64url.encode(crypto.getRandomValues(new Uint8Array(16)))
}

async function disclosure(name: string, value: string): Promise<{
  encoded: string
  digest: string
}> {
  const encoded = base64url.encode(JSON.stringify([randomSalt(), name, value]))
  return { encoded, digest: await sha256(encoded) }
}

export type IssuedSdJwtVc = Readonly<{
  mediaType: typeof SD_JWT_CREDENTIAL_MEDIA_TYPE
  /** Only this plus disclosures are given to the holder; ID stays private. */
  issuerSignedJwt: string
  disclosures: Readonly<{
    thresholdDate: string
    providerId: string
  }>
  /** Internal registry record identifier. NEVER include it in a VP. */
  privateCredentialId: string
}>

export type SdJwtOnchainAgePolicy = Readonly<{
  issuer: string
  issuerKid: string
  issuerPublicKey: CryptoKey
  audience: string
  nonce: string
  chainId: number
  methodologyVersion: string
  requiredThresholdDate: string
  now: Date
  statusChecker: CredentialStatusChecker
}>

export type SdJwtVerification =
  | Readonly<{ status: 'satisfied'; chainId: number; thresholdDate: string }>
  | Readonly<{ status: 'not_satisfied'; reason: 'policy_not_met' }>
  | Readonly<{ status: 'unverifiable'; reason: string }>

/**
 * Issuer-authorized reissuance into a distinct SD-JWT VC format. It validates
 * the original native signed VC and checks status *before* creating a new
 * credential. A new issuer identity/key must never be chosen by the holder.
 *
 * The newly issued signed JWT does not contain jti/wallet/transaction hashes.
 * That reduces obvious metadata but DOES NOT guarantee unlinkability:
 * repeated issuer JWT bytes and holder public keys remain linkable.
 */
export async function issueOnchainAgeSdJwtVc(input: {
  sourceVc2Jwt: string
  issuer: string
  issuerKid: string
  issuerPublicKey: CryptoKey
  issuerPrivateKey: CryptoKey
  sourceStatusChecker: CredentialStatusChecker
  newStatusRegistry: IssuedCredentialRegistry
  now: Date
}): Promise<IssuedSdJwtVc> {
  if (!input.sourceVc2Jwt || input.sourceVc2Jwt.length > MAX_TOKEN_SIZE ||
      !Number.isFinite(input.now.getTime())) throw new Error('Invalid SD-JWT VC reissuance parameters')

  const source = await jwtVerify(input.sourceVc2Jwt, input.issuerPublicKey, {
    issuer: input.issuer,
    typ: 'vc+jwt',
    algorithms: ['ES256'],
    currentDate: input.now,
  })
  if (source.protectedHeader.kid !== input.issuerKid) throw new Error('Untrusted original credential key')
  const payload = source.payload
  const subject = record(payload.credentialSubject)
  const confirmation = record(payload.cnf)
  if (!subject || !holderJwk(confirmation?.jwk) ||
      payload.issuer !== input.issuer ||
      typeof payload.id !== 'string' || payload.id !== payload.jti ||
      subject.primitive !== 'OnchainAge' ||
      subject.schemaVersion !== 'onchain-age-credential/0.1.0' ||
      subject.methodologyVersion !== 'onchain-age/0.1.0' ||
      subject.chainId !== 1 ||
      !iso(subject.thresholdDate) ||
      !iso(payload.validFrom) || !iso(payload.validUntil) ||
      Date.parse(payload.validFrom) > input.now.getTime() ||
      Date.parse(payload.validUntil) <= input.now.getTime() ||
      typeof payload.exp !== 'number') throw new Error('Unsupported source credential claims')

  const sourceStatus = await input.sourceStatusChecker.check({
    credentialJwt: input.sourceVc2Jwt,
    issuer: input.issuer,
    issuerKeyId: input.issuerKid,
  })
  if (sourceStatus !== 'valid') throw new Error('Source credential revoked or status unknown')

  const coverage = record(subject.sourceCoverage)
  if (!coverage || typeof coverage.providerId !== 'string' ||
      !coverage.providerId.trim()) throw new Error('Unverified source coverage')

  const [age, provider] = await Promise.all([
    disclosure('thresholdDate', subject.thresholdDate),
    disclosure('providerId', coverage.providerId),
  ])
  const until = Math.min(
    payload.exp,
    Math.floor(input.now.getTime() / 1000) + 24 * 60 * 60,
  )
  const issued = Math.floor(input.now.getTime() / 1000)
  if (until <= issued) throw new Error('No remaining credential lifetime')

  const issuerJwt = await new SignJWT({
    vct: SD_JWT_VC_TYPE,
    primitive: 'OnchainAge',
    chainId: 1,
    methodologyVersion: 'onchain-age/0.1.0',
    cnf: { jwk: confirmation.jwk },
    _sd_alg: 'sha-256',
    _sd: [age.digest, provider.digest],
  })
    .setProtectedHeader({ typ: 'dc+sd-jwt', alg: 'ES256', kid: input.issuerKid })
    .setIssuer(input.issuer)
    .setIssuedAt(issued)
    .setExpirationTime(until)
    .sign(input.issuerPrivateKey)

  // Registry ID is not included in the signed token or presentations.
  const credentialId = 'urn:uuid:' + crypto.randomUUID()
  await input.newStatusRegistry.recordIssued({
    credentialJwt: issuerJwt,
    issuer: input.issuer,
    issuerKeyId: input.issuerKid,
    credentialId,
  })
  return {
    mediaType: SD_JWT_CREDENTIAL_MEDIA_TYPE,
    issuerSignedJwt: issuerJwt,
    disclosures: { thresholdDate: age.encoded, providerId: provider.encoded },
    privateCredentialId: credentialId,
  }
}

/**
 * RFC9901 SD-JWT+KB compact serialization:
 * <issuerJwt>~<selected disclosure>~<KB-JWT>.
 * The SD hash is calculated over issuerJwt + "~" + disclosures + "~".
 */
export async function presentOnchainAgeSdJwtVc(input: {
  credential: IssuedSdJwtVc
  /** Default privacy profile reveals required threshold only, never provider. */
  discloseProvider?: boolean
  holderPrivateKey: CryptoKey
  nonce: string
  audience: string
  now: Date
}): Promise<string> {
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(input.nonce) ||
      !input.audience.trim() || !Number.isFinite(input.now.getTime())) {
    throw new Error('Invalid presentation challenge')
  }
  const parts = [
    input.credential.issuerSignedJwt,
    input.credential.disclosures.thresholdDate,
  ]
  if (input.discloseProvider === true) parts.push(input.credential.disclosures.providerId)
  const sdJwt = parts.join('~') + '~'
  const iat = Math.floor(input.now.getTime() / 1000)
  const hash = await sha256(sdJwt)
  const keyBinding = await new SignJWT({
    nonce: input.nonce,
    sd_hash: hash,
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
    .setAudience(input.audience)
    .setIssuedAt(iat)
    .setExpirationTime(iat + MAX_PROOF_SECONDS)
    .sign(input.holderPrivateKey)
  return sdJwt + keyBinding
}

export async function verifyOnchainAgeSdJwtVc(
  presentation: string,
  policy: SdJwtOnchainAgePolicy,
): Promise<SdJwtVerification> {
  const fail = (reason: string): SdJwtVerification => ({ status: 'unverifiable', reason })
  if (presentation.length > MAX_TOKEN_SIZE ||
      !Number.isFinite(policy.now.getTime()) ||
      !iso(policy.requiredThresholdDate) ||
      !policy.issuerKid || !policy.issuer ||
      !/^[A-Za-z0-9_-]{32,128}$/.test(policy.nonce) ||
      !policy.audience) return fail('invalid_input')

  const segments = presentation.split('~')
  if (segments.length < 3 || segments.length > 5 ||
      segments.some(s => !s)) return fail('invalid_sd_jwt_serialization')

  const issuerJwt = segments[0]!
  const kbJwt = segments[segments.length - 1]!
  const disclosures = segments.slice(1, -1)
  const signedSdJwt = segments.slice(0, -1).join('~') + '~'

  let payload: JWTPayload
  let key: CryptoKey
  try {
    const verified = await jwtVerify(issuerJwt, policy.issuerPublicKey, {
      issuer: policy.issuer,
      typ: 'dc+sd-jwt',
      algorithms: ['ES256'],
      currentDate: policy.now,
    })
    if (verified.protectedHeader.kid !== policy.issuerKid) return fail('untrusted_issuer_key')
    payload = verified.payload
    const cnf = record(payload.cnf)
    if (payload.vct !== SD_JWT_VC_TYPE ||
        payload.primitive !== 'OnchainAge' ||
        payload._sd_alg !== 'sha-256' ||
        !Array.isArray(payload._sd) ||
        payload._sd.length !== 2 ||
        new Set(payload._sd).size !== 2 ||
        !payload._sd.every(d => typeof d === 'string' && /^[A-Za-z0-9_-]{43}$/.test(d)) ||
        !holderJwk(cnf?.jwk) ||
        typeof payload.iat !== 'number' ||
        typeof payload.exp !== 'number' ||
        !Number.isSafeInteger(payload.iat) ||
        !Number.isSafeInteger(payload.exp) ||
        payload.iat > policy.now.getTime() / 1000 + CLOCK_SKEW_SECONDS ||
        payload.exp <= payload.iat ||
        typeof payload.methodologyVersion !== 'string' ||
        !Number.isSafeInteger(payload.chainId)) return fail('invalid_signed_credential')
    key = await importJWK(cnf.jwk, 'ES256') as CryptoKey
  } catch { return fail('invalid_issuer_signature_or_claims') }

  const disclosed = new Map<string, unknown>()
  try {
    for (const encoded of disclosures) {
      const hash = await sha256(encoded)
      if (!(payload._sd as string[]).includes(hash)) return fail('uncommitted_disclosure')
      const raw = JSON.parse(new TextDecoder().decode(base64url.decode(encoded))) as unknown
      if (!Array.isArray(raw) || raw.length !== 3 ||
          typeof raw[0] !== 'string' || !raw[0] ||
          typeof raw[1] !== 'string' ||
          !['thresholdDate', 'providerId'].includes(raw[1]) ||
          disclosed.has(raw[1]) ||
          typeof raw[2] !== 'string') return fail('invalid_disclosure')
      disclosed.set(raw[1], raw[2])
    }
  } catch { return fail('invalid_disclosure') }

  // Only a disclosed, issuer-committed age threshold may satisfy a policy.
  const threshold = disclosed.get('thresholdDate')
  if (!iso(threshold)) return fail('missing_required_disclosure')

  try {
    const verified = await jwtVerify(kbJwt, key, {
      typ: 'kb+jwt',
      algorithms: ['ES256'],
      audience: policy.audience,
      currentDate: policy.now,
    })
    const kb = verified.payload
    if (kb.aud !== policy.audience ||
        kb.nonce !== policy.nonce ||
        kb.sd_hash !== await sha256(signedSdJwt) ||
        !Number.isSafeInteger(kb.iat) ||
        !Number.isSafeInteger(kb.exp) ||
        typeof kb.iat !== 'number' ||
        typeof kb.exp !== 'number' ||
        kb.exp <= kb.iat ||
        kb.exp - kb.iat > MAX_PROOF_SECONDS ||
        kb.iat > policy.now.getTime() / 1000 + CLOCK_SKEW_SECONDS) {
      return fail('invalid_key_binding')
    }
  } catch { return fail('invalid_key_binding') }

  if (payload.chainId !== policy.chainId ||
      payload.methodologyVersion !== policy.methodologyVersion ||
      Date.parse(threshold) > Date.parse(policy.requiredThresholdDate)) {
    return { status: 'not_satisfied', reason: 'policy_not_met' }
  }

  let status: string
  try {
    status = await policy.statusChecker.check({
      credentialJwt: issuerJwt,
      issuer: policy.issuer,
      issuerKeyId: policy.issuerKid,
    })
  } catch { status = 'unknown' }
  if (status !== 'valid') return fail(status === 'revoked' ? 'credential_revoked' : 'credential_status_unknown')
  return { status: 'satisfied', chainId: payload.chainId as number, thresholdDate: threshold }
}
