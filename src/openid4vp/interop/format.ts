import {
  decodeProtectedHeader,
  importJWK,
  jwtVerify,
  SignJWT,
  type JWK,
  type JWTPayload,
} from 'jose'
import { ONCHAIN_AGE_CREDENTIAL_TYPE, ONCHAIN_AGE_CREDENTIAL_SCHEMA_VERSION } from '../../credentials/types.js'
import type { CredentialStatusChecker } from '../../verifier/types.js'
import {
  OID4VP_VC_V1_CONTEXT,
  type OnchainAgeVpResult,
  type OpenId4VpTransaction,
} from './types.js'

const HOLDER_PROOF_TTL_SECONDS = 120
const SKEW_MS = 30_000
const MAX_JWT_BYTES = 32_768

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : undefined
}

function p256Jwk(value: unknown): value is JWK {
  const j = record(value)
  return !!j && j.kty === 'EC' && j.crv === 'P-256' &&
    typeof j.x === 'string' && typeof j.y === 'string' &&
    j.d === undefined && j.k === undefined
}

function validIso(value: unknown): value is string {
  if (typeof value !== 'string') return false
  const date = new Date(value)
  return Number.isFinite(date.getTime()) && date.toISOString() === value
}

/**
 * Separate, issuer-authorized legacy JWT VC encoding solely for the format
 * profile in OpenID4VP Appendix B.1.3.1 (jwt_vc_json).
 *
 * This is not the same serialization as our native VC 2.0 application/vc+jwt,
 * and MUST NOT be a blind relabeling of that token. The issuer verifies a
 * genuine prior issuance using a pinned key before signing this encoding.
 * The two formats intentionally share the same underlying claim and jti.
 */
export async function reissueForJwtVcJsonPilot(input: {
  sourceVc2Jwt: string
  issuer: string
  issuerKid: string
  issuerPublicKey: CryptoKey
  issuerPrivateKey: CryptoKey
  now: Date
}): Promise<string> {
  const source = await jwtVerify(input.sourceVc2Jwt, input.issuerPublicKey, {
    issuer: input.issuer,
    typ: 'vc+jwt',
    algorithms: ['ES256'],
    currentDate: input.now,
  })
  if (source.protectedHeader.kid !== input.issuerKid) {
    throw new Error('Untrusted source credential signing key')
  }
  const original = source.payload
  const subject = record(original.credentialSubject)
  const cnf = record(original.cnf)
  if (!subject || subject.primitive !== 'OnchainAge' ||
      subject.schemaVersion !== ONCHAIN_AGE_CREDENTIAL_SCHEMA_VERSION ||
      !Number.isSafeInteger(subject.chainId) ||
      !validIso(subject.thresholdDate) ||
      !validIso(original.validFrom) ||
      !validIso(original.validUntil) ||
      !p256Jwk(cnf?.jwk) ||
      typeof original.iat !== 'number' ||
      typeof original.exp !== 'number' ||
      !validIso(original.validFrom) ||
      original.issuer !== input.issuer) {
    throw new Error('Invalid source VC 2.0 profile')
  }

  const payload = {
    cnf: { jwk: cnf.jwk },
    vc: {
      '@context': [OID4VP_VC_V1_CONTEXT],
      type: ['VerifiableCredential', ONCHAIN_AGE_CREDENTIAL_TYPE],
      issuer: input.issuer,
      credentialSubject: subject,
    },
  }
  let signed = new SignJWT(payload)
    .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: input.issuerKid })
    .setIssuer(input.issuer)
    .setIssuedAt(original.iat)
    .setExpirationTime(original.exp)
  if (typeof original.jti === 'string') signed = signed.setJti(original.jti)
  return signed.sign(input.issuerPrivateKey)
}

/** Sign the actual JWT VP shape of OpenID4VP Appendix B.1.3.1.5. */
export async function createJwtVpJsonPresentation(input: {
  jwtVcJson: string
  holderPrivateKey: CryptoKey
  nonce: string
  audience: string
  now: Date
}): Promise<string> {
  if (!/^[A-Za-z0-9_-]{40,80}$/.test(input.nonce) ||
      !input.audience.startsWith('verifier_attestation:') ||
      input.jwtVcJson.length > MAX_JWT_BYTES) {
    throw new Error('Invalid VP request')
  }
  const iat = Math.floor(input.now.getTime() / 1000)
  if (!Number.isSafeInteger(iat)) throw new Error('Invalid VP clock')
  return new SignJWT({
    nonce: input.nonce,
    vp: {
      '@context': [OID4VP_VC_V1_CONTEXT],
      type: ['VerifiablePresentation'],
      verifiableCredential: [input.jwtVcJson],
    },
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
    .setAudience(input.audience)
    .setIssuedAt(iat)
    .setExpirationTime(iat + HOLDER_PROOF_TTL_SECONDS)
    .sign(input.holderPrivateKey)
}

/** Single supported DCQL query, not general-purpose arbitrary format matching. */
export async function verifyJwtVcJsonPresentation(input: {
  vpJwt: string
  tx: OpenId4VpTransaction
  statusChecker: CredentialStatusChecker
  now: Date
}): Promise<OnchainAgeVpResult> {
  const fail = (reason: string): OnchainAgeVpResult => ({ status: 'unverifiable', reason })
  if (input.vpJwt.length > MAX_JWT_BYTES || !Number.isFinite(input.now.getTime())) return fail('invalid_vp')
  let untrusted: JWTPayload
  try {
    // The token is decoded ONLY to locate its inner VC. We do not rely on
    // any unverified claim until the issuer and holder signatures are checked.
    // Outer VP JWT must be validated against cnf.jwk of the verified VC below.
    const parts = input.vpJwt.split('.')
    if (parts.length !== 3) return fail('invalid_vp')
    const decoded = JSON.parse(new TextDecoder().decode(
      Uint8Array.from(atob(parts[1]!.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
    )) as unknown
    if (!record(decoded)) return fail('invalid_vp')
    untrusted = decoded as JWTPayload
  } catch {
    return fail('invalid_vp')
  }
  const vp = record(untrusted.vp)
  const verifiableCredential = vp?.verifiableCredential
  if (
    !vp || JSON.stringify(vp['@context']) !== JSON.stringify([OID4VP_VC_V1_CONTEXT]) ||
    JSON.stringify(vp.type) !== JSON.stringify(['VerifiablePresentation']) ||
    !Array.isArray(verifiableCredential) ||
    verifiableCredential.length !== 1 ||
    typeof verifiableCredential[0] !== 'string'
  ) return fail('invalid_vp_shape')

  const legacyJwt = verifiableCredential[0]
  if (legacyJwt.length > MAX_JWT_BYTES) return fail('invalid_credential')
  let credential: JWTPayload
  let holderJwk: JWK
  try {
    const trusted = await jwtVerify(legacyJwt, input.tx.policy.issuerPublicKey, {
      issuer: input.tx.policy.issuer,
      typ: 'JWT',
      algorithms: ['ES256'],
      currentDate: input.now,
    })
    if (trusted.protectedHeader.kid !== input.tx.policy.issuerKeyId) {
      return fail('untrusted_issuer_key')
    }
    credential = trusted.payload
    const legacyVc = record(credential.vc)
    const subject = record(legacyVc?.credentialSubject)
    const confirmation = record(credential.cnf)
    if (!legacyVc ||
        JSON.stringify(legacyVc['@context']) !== JSON.stringify([OID4VP_VC_V1_CONTEXT]) ||
        JSON.stringify(legacyVc.type) !== JSON.stringify(['VerifiableCredential', ONCHAIN_AGE_CREDENTIAL_TYPE]) ||
        legacyVc.issuer !== input.tx.policy.issuer ||
        !subject ||
        subject.primitive !== 'OnchainAge' ||
        subject.schemaVersion !== ONCHAIN_AGE_CREDENTIAL_SCHEMA_VERSION ||
        !Number.isSafeInteger(subject.chainId) ||
        !validIso(subject.thresholdDate) ||
        typeof subject.methodologyVersion !== 'string' ||
        !p256Jwk(confirmation?.jwk)) {
      return fail('invalid_signed_claim')
    }
    holderJwk = confirmation.jwk
  } catch {
    return fail('invalid_credential')
  }

  let verifiedVp: JWTPayload
  try {
    const holderKey = await importJWK(holderJwk, 'ES256')
    const signed = await jwtVerify(input.vpJwt, holderKey, {
      audience: input.tx.clientId,
      typ: 'JWT',
      algorithms: ['ES256'],
      currentDate: input.now,
    })
    verifiedVp = signed.payload
    const iat = verifiedVp.iat
    const exp = verifiedVp.exp
    if (
      verifiedVp.aud !== input.tx.clientId ||
      verifiedVp.nonce !== input.tx.nonce ||
      !Number.isSafeInteger(iat) || !Number.isSafeInteger(exp) ||
      typeof iat !== 'number' || typeof exp !== 'number' ||
      exp <= iat || exp - iat > HOLDER_PROOF_TTL_SECONDS + 1 ||
      iat * 1000 < input.tx.issuedAt - SKEW_MS ||
      iat * 1000 > input.now.getTime() + SKEW_MS ||
      // Only the exact previously validated VC belongs in the signed VP.
      JSON.stringify(verifiedVp.vp) !== JSON.stringify(vp)
    ) return fail('holder_proof_invalid')
  } catch {
    return fail('holder_proof_invalid')
  }

  const claim = record(record(credential.vc)?.credentialSubject)!
  if (
    claim.chainId !== input.tx.policy.chainId ||
    claim.methodologyVersion !== input.tx.policy.methodologyVersion ||
    Date.parse(claim.thresholdDate as string) > Date.parse(input.tx.policy.requiredThresholdDate)
  ) return { status: 'not_satisfied', reason: 'policy_not_met' }

  let status: string
  try {
    status = await input.statusChecker.check({
      credentialJwt: legacyJwt,
      issuer: input.tx.policy.issuer,
      issuerKeyId: input.tx.policy.issuerKeyId,
    })
  } catch { status = 'unknown' }
  if (status !== 'valid') return fail(status === 'revoked' ? 'credential_revoked' : 'credential_status_unknown')
  return {
    status: 'satisfied',
    chainId: claim.chainId as number,
    thresholdDate: claim.thresholdDate as string,
  }
}
