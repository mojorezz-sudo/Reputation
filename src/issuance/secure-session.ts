import { isAddress } from 'viem'
import {
  base64url,
  decodeJwt,
  decodeProtectedHeader,
  exportJWK,
  importJWK,
  jwtVerify,
  SignJWT,
  type JWK,
} from 'jose'

import {
  OnchainAgeCredentialIssuer,
  type OnchainAgeCredentialIssuanceResult,
  type SuccessfulOwnershipVerification,
} from '../credentials/index.js'
import type { CredentialStatus, CredentialStatusChecker } from '../verifier/types.js'

export const ISSUANCE_KEY_PROOF_TYPE = 'openid4vci-proof+jwt' as const
export const DEFAULT_ISSUANCE_SESSION_TTL_MS = 120_000
export const MAX_ISSUANCE_SESSION_TTL_MS = 300_000
const MAX_PROOF_TTL_SECONDS = 120
const CLOCK_SKEW_MS = 30_000
const MAX_JWT_BYTES = 16_384

export type IssuanceRequest = Readonly<{
  nonce: string
  audience: string
  issuedAt: string
  expiresAt: string
}>

export type PrivateIssuanceSession = Readonly<{
  nonce: string
  audience: string
  holderSessionId: string
  issuedAt: string
  expiresAt: string
  verifiedOwnership: SuccessfulOwnershipVerification
  thresholdDate: string
}>

export interface IssuanceSessionStore {
  save(session: PrivateIssuanceSession): Promise<void>
  /**
   * Must atomically consume a nonce for precisely this authenticated holder
   * session. Wrong sessions MUST NOT consume someone else's challenge.
   */
  take(nonce: string, holderSessionId: string): Promise<PrivateIssuanceSession | undefined>
}

/** Development only: not durable across replicas/restarts. */
export class InMemoryIssuanceSessionStore implements IssuanceSessionStore {
  readonly #sessions = new Map<string, PrivateIssuanceSession>()

  async save(session: PrivateIssuanceSession): Promise<void> {
    if (this.#sessions.has(session.nonce)) throw new Error('Issuance nonce collision')
    this.#sessions.set(session.nonce, session)
  }

  async take(nonce: string, holderSessionId: string): Promise<PrivateIssuanceSession | undefined> {
    const value = this.#sessions.get(nonce)
    if (!value || value.holderSessionId !== holderSessionId) return undefined
    this.#sessions.delete(nonce)
    return value
  }
}

function toIso(value: Date): string {
  if (!Number.isFinite(value.getTime())) throw new Error('Invalid timestamp')
  return value.toISOString()
}

function validPublicP256Key(value: unknown): value is JWK {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const jwk = value as Record<string, unknown>
  return jwk.kty === 'EC' && jwk.crv === 'P-256' &&
    typeof jwk.x === 'string' && typeof jwk.y === 'string' &&
    !('d' in jwk) && !('k' in jwk)
}

export type SecureIssuanceResult =
  | Readonly<{ status: 'issued'; credential: Extract<OnchainAgeCredentialIssuanceResult, {status: 'issued'}> }>
  | Readonly<{
      status: 'not_issued'
      reason:
        | 'invalid_or_consumed_session'
        | 'session_expired'
        | 'invalid_key_proof'
        | 'reputation_not_satisfied'
        | 'reputation_unverifiable'
      }>

export interface IssuedCredentialRegistry extends CredentialStatusChecker {
  /** Record a credential minted by our own trusted issuance pipeline only. */
  recordIssued(input: { credentialJwt: string; issuer: string; issuerKeyId: string; credentialId: string }): Promise<void>
}

async function tokenDigest(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return base64url.encode(new Uint8Array(digest))
}

/**
 * Sandbox status registry. Check is local; there are no per-credential remote
 * calls and no HTTP tracking. NOT a deployed revocation/Bitstring Status List.
 */
export class InMemoryIssuedCredentialRegistry implements IssuedCredentialRegistry {
  readonly #byDigest = new Map<string, {
    issuer: string
    issuerKeyId: string
    credentialId: string
    revoked: boolean
  }>()
  readonly #byId = new Map<string, string>()

  async recordIssued(input: {
    credentialJwt: string
    issuer: string
    issuerKeyId: string
    credentialId: string
  }): Promise<void> {
    if (!input.credentialId.startsWith('urn:uuid:')) throw new Error('Missing signed credential ID')
    const id = input.credentialId
    if (this.#byId.has(id)) throw new Error('Duplicate credential ID')
    const digest = await tokenDigest(input.credentialJwt)
    if (this.#byDigest.has(digest)) throw new Error('Duplicate credential bytes')
    this.#byDigest.set(digest, {
      issuer: input.issuer,
      issuerKeyId: input.issuerKeyId,
      credentialId: id,
      revoked: false,
    })
    this.#byId.set(id, digest)
  }

  async revoke(credentialId: string): Promise<boolean> {
    const digest = this.#byId.get(credentialId)
    if (!digest) return false
    const stored = this.#byDigest.get(digest)
    if (!stored) return false
    stored.revoked = true
    return true
  }

  async check(input: {
    credentialJwt: string
    issuer: string
    issuerKeyId: string
  }): Promise<CredentialStatus> {
    const digest = await tokenDigest(input.credentialJwt)
    const stored = this.#byDigest.get(digest)
    if (!stored || stored.issuer !== input.issuer || stored.issuerKeyId !== input.issuerKeyId) {
      return 'unknown'
    }
    return stored.revoked ? 'revoked' : 'valid'
  }
}

/**
 * OID4VCI-shaped JWT key proof: signed with the P-256 key that the credential
 * will bind to. This utility does NOT implement the OAuth/token endpoint and
 * should not be marketed as complete OpenID4VCI interoperability.
 */
export async function createIssuanceKeyProof(input: {
  request: IssuanceRequest
  holderPrivateKey: CryptoKey
  holderPublicKey: CryptoKey
  now?: Date
}): Promise<string> {
  const now = input.now ?? new Date()
  const nowMs = now.getTime()
  const expiration = Date.parse(input.request.expiresAt)
  const issued = Date.parse(input.request.issuedAt)
  if (
    !Number.isFinite(nowMs) || !Number.isFinite(expiration) ||
    !Number.isFinite(issued) || nowMs < issued || nowMs >= expiration
  ) throw new Error('Issuance request expired or invalid')
  const jwk = await exportJWK(input.holderPublicKey)
  if (!validPublicP256Key(jwk)) throw new Error('Holder must use a public P-256 key')
  const iat = Math.floor(nowMs / 1000)
  const exp = Math.min(iat + MAX_PROOF_TTL_SECONDS, Math.ceil(expiration / 1000))
  return new SignJWT({ nonce: input.request.nonce })
    .setProtectedHeader({ alg: 'ES256', typ: ISSUANCE_KEY_PROOF_TYPE, jwk })
    .setAudience(input.request.audience)
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .sign(input.holderPrivateKey)
}

/**
 * Application-internal coordinator. Never expose start() with a user-supplied
 * ownership result. An authenticated backend must pass a verified, fresh
 * ownership event created by its own SIWE/session boundary.
 */
export class SecureOnchainAgeIssuanceCoordinator {
  readonly #audience: string
  readonly #issuerKeyId: string
  readonly #issuer: OnchainAgeCredentialIssuer
  readonly #store: IssuanceSessionStore
  readonly #registry: IssuedCredentialRegistry
  readonly #clock: () => Date

  constructor(options: {
    audience: string
    issuerKeyId: string
    credentialIssuer: OnchainAgeCredentialIssuer
    store: IssuanceSessionStore
    registry: IssuedCredentialRegistry
    clock?: () => Date
  }) {
    if (!options.audience.startsWith('https://') ||
        !options.issuerKeyId.startsWith('https://')) {
      throw new Error('Issuer audience and key ID must use HTTPS')
    }
    this.#audience = options.audience
    this.#issuerKeyId = options.issuerKeyId
    this.#issuer = options.credentialIssuer
    this.#store = options.store
    this.#registry = options.registry
    this.#clock = options.clock ?? (() => new Date())
  }

  async start(input: {
    /** Opaque authenticated server-side holder session reference. */
    holderSessionId: string
    /** The server's trusted output from SIWE verification. */
    verifiedOwnership: SuccessfulOwnershipVerification
    thresholdDate: Date
    ttlMs?: number
  }): Promise<IssuanceRequest> {
    const now = this.#clock()
    const nowMs = now.getTime()
    const ttlMs = input.ttlMs ?? DEFAULT_ISSUANCE_SESSION_TTL_MS
    if (
      !Number.isFinite(nowMs) ||
      !input.holderSessionId.trim() ||
      !Number.isSafeInteger(ttlMs) || ttlMs <= 0 || ttlMs > MAX_ISSUANCE_SESSION_TTL_MS ||
      input.verifiedOwnership.ok !== true ||
      !isAddress(input.verifiedOwnership.address) ||
      !Number.isFinite(input.verifiedOwnership.verifiedAt.getTime()) ||
      input.verifiedOwnership.verifiedAt.getTime() > nowMs ||
      nowMs - input.verifiedOwnership.verifiedAt.getTime() > 10 * 60_000 ||
      !Number.isSafeInteger(input.verifiedOwnership.chainId) ||
      input.verifiedOwnership.chainId <= 0 ||
      !Number.isFinite(input.thresholdDate.getTime()) ||
      input.thresholdDate.getTime() > nowMs
    ) throw new Error('Invalid or stale issuance session input')

    const nonce = base64url.encode(crypto.getRandomValues(new Uint8Array(32)))
    const issuedAt = toIso(now)
    const expiresAt = toIso(new Date(nowMs + ttlMs))
    await this.#store.save({
      nonce,
      audience: this.#audience,
      holderSessionId: input.holderSessionId,
      issuedAt,
      expiresAt,
      verifiedOwnership: input.verifiedOwnership,
      thresholdDate: toIso(input.thresholdDate),
    })
    return { nonce, audience: this.#audience, issuedAt, expiresAt }
  }

  async complete(input: { holderSessionId: string; proofJwt: string }): Promise<SecureIssuanceResult> {
    if (!input.holderSessionId.trim() ||
        typeof input.proofJwt !== 'string' ||
        input.proofJwt.length > MAX_JWT_BYTES) {
      return { status: 'not_issued', reason: 'invalid_key_proof' }
    }
    let nonce: string
    try {
      const candidate = decodeJwt(input.proofJwt).nonce
      if (typeof candidate !== 'string' || !/^[A-Za-z0-9_-]{40,80}$/.test(candidate)) {
        throw new Error('Invalid nonce')
      }
      nonce = candidate
    } catch {
      return { status: 'not_issued', reason: 'invalid_key_proof' }
    }

    // Atomic take is the trust boundary. The unverified nonce is only a
    // *locator*; its authenticity is checked below against the signed JWT.
    const session = await this.#store.take(nonce, input.holderSessionId)
    if (!session) return { status: 'not_issued', reason: 'invalid_or_consumed_session' }

    const now = this.#clock()
    const nowMs = now.getTime()
    const issuedMs = Date.parse(session.issuedAt)
    const expirationMs = Date.parse(session.expiresAt)
    if (!Number.isFinite(nowMs) || !Number.isFinite(issuedMs) ||
        !Number.isFinite(expirationMs) ||
        nowMs < issuedMs || nowMs >= expirationMs) {
      return { status: 'not_issued', reason: 'session_expired' }
    }

    let holderPublicJwk: JWK
    try {
      const header = decodeProtectedHeader(input.proofJwt)
      if (header.alg !== 'ES256' || header.typ !== ISSUANCE_KEY_PROOF_TYPE ||
          header.kid !== undefined || header.x5c !== undefined ||
          !validPublicP256Key(header.jwk)) {
        throw new Error('Unacceptable proof header')
      }
      const imported = await importJWK(header.jwk, 'ES256')
      const checked = await jwtVerify(input.proofJwt, imported, {
        algorithms: ['ES256'],
        typ: ISSUANCE_KEY_PROOF_TYPE,
        audience: this.#audience,
        currentDate: now,
      })
      const p = checked.payload
      if (
        p.nonce !== session.nonce ||
        p.aud !== session.audience ||
        !Number.isSafeInteger(p.iat) ||
        !Number.isSafeInteger(p.exp) ||
        p.exp! <= p.iat! ||
        p.exp! - p.iat! > MAX_PROOF_TTL_SECONDS + 1 ||
        p.iat! * 1000 < issuedMs - CLOCK_SKEW_MS ||
        p.iat! * 1000 > nowMs + CLOCK_SKEW_MS
      ) throw new Error('Invalid proof claims')
      holderPublicJwk = header.jwk
    } catch {
      return { status: 'not_issued', reason: 'invalid_key_proof' }
    }

    const outcome = await this.#issuer.issue({
      ownership: session.verifiedOwnership,
      thresholdDate: new Date(session.thresholdDate),
      holderPublicJwk,
    })
    if (outcome.status !== 'issued') {
      return { status: 'not_issued', reason: outcome.reason }
    }
    if (!outcome.model.id) throw new Error('Issuer returned credential without signed ID')
    // The trusted issuer component must be configured for this exact issuer
    // and key ID. Decode here is only an internal consistency check, not
    // signature verification of externally supplied credentials.
    const issuedPayload = decodeJwt(outcome.credential.value)
    const issuedHeader = decodeProtectedHeader(outcome.credential.value)
    if (
      outcome.model.issuer !== this.#audience ||
      issuedPayload.iss !== this.#audience ||
      issuedPayload.id !== outcome.model.id ||
      issuedPayload.jti !== outcome.model.id ||
      issuedHeader.kid !== this.#issuerKeyId
    ) throw new Error('Issuer signing configuration or credential ID mismatch')
    await this.#registry.recordIssued({
      credentialJwt: outcome.credential.value,
      credentialId: outcome.model.id,
      issuer: this.#audience,
      issuerKeyId: this.#issuerKeyId,
    })
    return { status: 'issued', credential: outcome }
  }
}
