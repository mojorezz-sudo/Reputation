import { importJWK, jwtVerify, type JWTPayload, type JWK } from 'jose'
import {
  ONCHAIN_AGE_CREDENTIAL_SCHEMA_VERSION,
  ONCHAIN_AGE_CREDENTIAL_TYPE,
  VC_V2_CONTEXT,
} from '../credentials/types.js'
import {
  issuePresentationRequest,
  parseExactIsoTime,
} from './challenge.js'
import {
  credentialDigest,
  HOLDER_PROOF_TYPE,
  MAX_HOLDER_PROOF_TTL_SECONDS,
} from './presentation.js'
import type {
  CredentialStatusChecker,
  HolderPresentation,
  OnchainAgeVerifierPolicy,
  PresentationChallengeStore,
  PresentationRequest,
  VerificationResult,
} from './types.js'

const MAX_PROOF_CLOCK_SKEW_SECONDS = 30
const MAX_TOKEN_LENGTH = 32_768

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function publicHolderJwk(value: unknown): JWK | undefined {
  if (!isRecord(value) || value.kty !== 'EC' || value.crv !== 'P-256' ||
      typeof value.x !== 'string' || typeof value.y !== 'string' ||
      typeof value.d !== 'undefined') return undefined
  return value as JWK
}

function isDecimalBlock(value: unknown): value is string {
  return typeof value === 'string' && /^(?:0|[1-9]\d*)$/.test(value)
}

function parseCredential(payload: JWTPayload, issuer: string): {
  holderJwk: JWK
  chainId: number
  methodologyVersion: string
  thresholdDate: string
} | undefined {
  if (
    payload.issuer !== issuer ||
    !Array.isArray(payload['@context']) ||
    payload['@context'][0] !== VC_V2_CONTEXT ||
    !Array.isArray(payload.type) ||
    payload.type.length !== 2 ||
    payload.type[0] !== 'VerifiableCredential' ||
    payload.type[1] !== ONCHAIN_AGE_CREDENTIAL_TYPE
  ) return undefined

  const validFrom = parseExactIsoTime(payload.validFrom as string)
  const validUntil = parseExactIsoTime(payload.validUntil as string)
  if (validFrom === undefined || validUntil === undefined || validFrom >= validUntil) return undefined

  const subject = payload.credentialSubject
  const cnf = payload.cnf
  if (!isRecord(subject) || !isRecord(cnf)) return undefined
  const holderJwk = publicHolderJwk(cnf.jwk)
  if (!holderJwk) return undefined

  const coverage = subject.sourceCoverage
  if (
    subject.primitive !== 'OnchainAge' ||
    subject.schemaVersion !== ONCHAIN_AGE_CREDENTIAL_SCHEMA_VERSION ||
    !Number.isSafeInteger(subject.chainId) ||
    typeof subject.chainId !== 'number' ||
    subject.chainId <= 0 ||
    typeof subject.methodologyVersion !== 'string' ||
    parseExactIsoTime(subject.thresholdDate as string) === undefined ||
    !isRecord(coverage) ||
    typeof coverage.providerId !== 'string' || !coverage.providerId.trim() ||
    !isDecimalBlock(coverage.fromBlock) ||
    !isDecimalBlock(coverage.throughBlock) ||
    BigInt(coverage.throughBlock) < BigInt(coverage.fromBlock) ||
    typeof coverage.complete !== 'boolean'
  ) return undefined

  return {
    holderJwk,
    chainId: subject.chainId,
    methodologyVersion: subject.methodologyVersion,
    thresholdDate: subject.thresholdDate as string,
  }
}

function credentialValidity(payload: JWTPayload, now: number): boolean {
  const from = parseExactIsoTime(payload.validFrom as string)
  const until = parseExactIsoTime(payload.validUntil as string)
  return from !== undefined && until !== undefined && from <= now && now < until
}

export type OnchainAgeVerifierOptions = Readonly<{
  /** Verifier client ID controlled by the dApp, not wallet input. */
  audience: string
  /** Trusted issuer public key and policy from server configuration. */
  policy: OnchainAgeVerifierPolicy
  store: PresentationChallengeStore
  /** Mandatory fail-closed revocation/status integration. */
  statusChecker: CredentialStatusChecker
  /** Test-only clock seam; server must supply trusted time in production. */
  clock?: () => Date
}>

/**
 * Sandbox verification of an issuer-signed VC JWT plus holder-signed proof.
 * This is deliberately NOT an OpenID4VP response or an unlinkable presentation.
 * A credential JWT and holder key reused across verifiers remain linkable.
 */
export class OnchainAgeVerifier {
  readonly #audience: string
  readonly #policy: OnchainAgeVerifierPolicy
  readonly #store: PresentationChallengeStore
  readonly #statusChecker: CredentialStatusChecker
  readonly #clock: () => Date

  constructor(options: OnchainAgeVerifierOptions) {
    if (!options.audience.startsWith('https://')) {
      throw new Error('Verifier audience must be an HTTPS identifier')
    }
    if (!options.statusChecker || typeof options.statusChecker.check !== 'function') {
      throw new Error('A credential status checker is required')
    }
    if (!Number.isSafeInteger(options.policy.chainId) || options.policy.chainId <= 0 ||
        parseExactIsoTime(options.policy.requiredThresholdDate) === undefined ||
        !options.policy.methodologyVersion.trim() ||
        !options.policy.issuer.startsWith('https://') ||
        !options.policy.issuerKeyId.startsWith('https://')) {
      throw new Error('Invalid verifier trust configuration')
    }
    this.#audience = options.audience
    this.#policy = { ...options.policy }
    this.#store = options.store
    this.#statusChecker = options.statusChecker
    this.#clock = options.clock ?? (() => new Date())
  }

  async createRequest(): Promise<PresentationRequest> {
    return issuePresentationRequest({
      audience: this.#audience,
      policy: this.#policy,
      store: this.#store,
      now: this.#clock(),
    })
  }

  async verify(input: HolderPresentation): Promise<VerificationResult> {
    const now = this.#clock()
    if (
      !Number.isFinite(now.getTime()) ||
      typeof input.nonce !== 'string' || input.nonce.length > 100 ||
      typeof input.credentialJwt !== 'string' ||
      typeof input.holderProofJwt !== 'string' ||
      input.credentialJwt.length > MAX_TOKEN_LENGTH ||
      input.holderProofJwt.length > MAX_TOKEN_LENGTH
    ) {
      return { status: 'unverifiable', reason: 'invalid_holder_proof' }
    }

    // Single-use atomic consumption precedes crypto work. This makes an
    // invalid attempt burn its own challenge; the holder can request a new one.
    // A different audience must not consume the correct verifier's challenge.
    const request = await this.#store.take(input.nonce, this.#audience)
    if (!request) {
      return { status: 'unverifiable', reason: 'challenge_not_found_or_consumed' }
    }

    const expiration = parseExactIsoTime(request.expiresAt)
    const requestedAt = parseExactIsoTime(request.issuedAt)
    if (expiration === undefined || requestedAt === undefined ||
        now.getTime() >= expiration || now.getTime() < requestedAt) {
      return { status: 'unverifiable', reason: 'challenge_expired' }
    }

    if (request.audience !== this.#audience ||
      request.policy.primitive !== 'OnchainAge' ||
      request.policy.chainId !== this.#policy.chainId ||
      request.policy.methodologyVersion !== this.#policy.methodologyVersion ||
      request.policy.requiredThresholdDate !== this.#policy.requiredThresholdDate) {
      return { status: 'unverifiable', reason: 'invalid_policy' }
    }

    let credentialPayload: JWTPayload
    let holderKey: CryptoKey | Uint8Array
    let parsedClaim: NonNullable<ReturnType<typeof parseCredential>>

    try {
      // Never resolve a key URL from the token! The key and kid are pinned
      // in trusted server configuration and alg is restricted to ES256.
      const credential = await jwtVerify(input.credentialJwt, this.#policy.issuerPublicKey, {
        issuer: this.#policy.issuer,
        typ: 'vc+jwt',
        algorithms: ['ES256'],
        currentDate: now,
      })
      if (credential.protectedHeader.kid !== this.#policy.issuerKeyId ||
          credentialPayloadMissing(credential.payload, now.getTime()) ||
          !credentialValidity(credential.payload, now.getTime())) {
        return { status: 'unverifiable', reason: 'invalid_credential' }
      }
      const claim = parseCredential(credential.payload, this.#policy.issuer)
      if (!claim) return { status: 'unverifiable', reason: 'invalid_credential' }
      holderKey = await importJWK(claim.holderJwk, 'ES256')
      credentialPayload = credential.payload
      parsedClaim = claim
    } catch {
      return { status: 'unverifiable', reason: 'invalid_credential' }
    }

    try {
      const proof = await jwtVerify(input.holderProofJwt, holderKey, {
        typ: HOLDER_PROOF_TYPE,
        algorithms: ['ES256'],
        audience: this.#audience,
        currentDate: now,
      })
      const payload = proof.payload
      const issuedSec = payload.iat
      const expiresSec = payload.exp
      const nowSec = now.getTime() / 1000
      if (
        payload.aud !== this.#audience ||
        payload.nonce !== request.nonce ||
        payload.credentialDigest !== await credentialDigest(input.credentialJwt) ||
        typeof issuedSec !== 'number' ||
        typeof expiresSec !== 'number' ||
        !Number.isSafeInteger(issuedSec) ||
        !Number.isSafeInteger(expiresSec) ||
        expiresSec <= issuedSec ||
        expiresSec - issuedSec > MAX_HOLDER_PROOF_TTL_SECONDS + 1 ||
        issuedSec > nowSec + MAX_PROOF_CLOCK_SKEW_SECONDS ||
        issuedSec * 1000 < requestedAt - MAX_PROOF_CLOCK_SKEW_SECONDS * 1000
      ) {
        return { status: 'unverifiable', reason: 'invalid_holder_proof' }
      }
    } catch {
      return { status: 'unverifiable', reason: 'invalid_holder_proof' }
    }

    // Not every valid credential meets the dApp's chosen policy.
    const signedThreshold = parseExactIsoTime(parsedClaim.thresholdDate)!
    const requiredThreshold = parseExactIsoTime(request.policy.requiredThresholdDate)!
    if (
      parsedClaim.chainId !== request.policy.chainId ||
      parsedClaim.methodologyVersion !== request.policy.methodologyVersion ||
      signedThreshold > requiredThreshold
    ) {
      return { status: 'not_satisfied', reason: 'policy_not_met' }
    }

    // No silent "revocation is probably fine" path. This checker must be
    // backed by real issuer/status infrastructure for any production pilot.
    let status: 'valid' | 'revoked' | 'unknown'
    try {
      status = await this.#statusChecker.check({
        credentialJwt: input.credentialJwt,
        issuer: this.#policy.issuer,
        issuerKeyId: this.#policy.issuerKeyId,
      })
    } catch {
      status = 'unknown'
    }
    if (status === 'revoked') {
      return { status: 'unverifiable', reason: 'credential_revoked' }
    }
    if (status !== 'valid') {
      return { status: 'unverifiable', reason: 'credential_status_unknown' }
    }

    return {
      status: 'satisfied',
      chainId: parsedClaim.chainId,
      methodologyVersion: parsedClaim.methodologyVersion,
      thresholdDate: parsedClaim.thresholdDate,
    }
  }
}

function credentialPayloadMissing(payload: JWTPayload, nowMs: number): boolean {
  return typeof payload.iss !== 'string' ||
    typeof payload.iat !== 'number' ||
    !Number.isSafeInteger(payload.iat) ||
    payload.iat * 1000 > nowMs + MAX_PROOF_CLOCK_SKEW_SECONDS * 1000 ||
    typeof payload.exp !== 'number' ||
    !Number.isSafeInteger(payload.exp) ||
    payload.exp <= payload.iat
}
