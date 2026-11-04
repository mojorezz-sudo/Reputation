import {
  CompactEncrypt,
  compactDecrypt,
  decodeProtectedHeader,
  importJWK,
  type JWK,
} from 'jose'
import type { CredentialStatusChecker } from '../../verifier/types.js'
import {
  OID4VP_VC_QUERY_ID,
  type OnchainAgeVpResult,
  type OpenId4VpRequestObject,
  type OpenId4VpTransactionStore,
} from './types.js'
import { verifyJwtVcJsonPresentation } from './format.js'

const MAX_POST_BODY_BYTES = 80_000
const MAX_RESPONSE_CODE_LIFETIME_MS = 2 * 60_000

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : undefined
}

function randomCode(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

function validHttps(uri: string): boolean {
  try {
    const x = new URL(uri)
    return x.protocol === 'https:' && !x.username && !x.password && !x.hash
  } catch {
    return false
  }
}

export type PendingVerifiedPresentation = Readonly<{
  code: string
  initiatedBySession: string
  expiresAt: number
  result: Extract<OnchainAgeVpResult, { status: 'satisfied' }>
}>

export interface VerifiedPresentationStore {
  save(record: PendingVerifiedPresentation): Promise<void>
  /** Must atomically consume only when both code AND browser session match. */
  take(code: string, initiatedBySession: string): Promise<PendingVerifiedPresentation | undefined>
}

/** Sandbox only: no persistence, no horizontal-scale atomicity. */
export class InMemoryVerifiedPresentationStore implements VerifiedPresentationStore {
  readonly #pending = new Map<string, PendingVerifiedPresentation>()

  async save(record: PendingVerifiedPresentation): Promise<void> {
    if (this.#pending.has(record.code)) throw new Error('Response code collision')
    this.#pending.set(record.code, record)
  }

  async take(code: string, session: string): Promise<PendingVerifiedPresentation | undefined> {
    const item = this.#pending.get(code)
    if (!item || item.initiatedBySession !== session) return undefined
    this.#pending.delete(code)
    return item
  }
}

/**
 * Wallet response body in standard direct_post.jwt shape:
 * x-www-form-urlencoded response=<compact JWE>.
 *
 * A valid requestObjectJwt has already been authenticated by the wallet.
 * This helper does not replace wallet consent / credential selection.
 */
export async function createEncryptedDirectPostResponse(input: {
  request: OpenId4VpRequestObject
  jwtVpJson: string
}): Promise<string> {
  if (input.request.response_mode !== 'direct_post.jwt') {
    throw new Error('Expected direct_post.jwt')
  }
  const [encryptionKey] = input.request.client_metadata.jwks.keys
  if (!encryptionKey || encryptionKey.kty !== 'EC' ||
      encryptionKey.crv !== 'P-256' ||
      typeof encryptionKey.kid !== 'string' || !encryptionKey.kid ||
      encryptionKey.d !== undefined) {
    throw new Error('Invalid verifier response encryption key')
  }
  const key = await importJWK(encryptionKey, 'ECDH-ES')
  const plaintext = new TextEncoder().encode(JSON.stringify({
    state: input.request.state,
    vp_token: { [OID4VP_VC_QUERY_ID]: [input.jwtVpJson] },
  }))
  const jwe = await new CompactEncrypt(plaintext)
    .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A128GCM', kid: encryptionKey.kid })
    .encrypt(key)
  return new URLSearchParams({ response: jwe }).toString()
}

export type ProcessDirectPostResponseResult =
  | Readonly<{ status: 'pending_user_confirmation'; redirect_uri: string }>
  | Readonly<{ status: 'not_satisfied'; reason: string }>
  | Readonly<{ status: 'unverifiable'; reason: string }>

/**
 * Server-side direct_post.jwt response processor.
 *
 * A cryptographically valid wallet response is NOT a user login. It creates
 * a one-time response code that MUST be confirmed from the authenticated
 * browser session that initiated the verifier request, preventing cross-
 * device login/session fixation. NEVER mark the session authenticated here.
 */
export class OpenId4VpDirectPostProcessor {
  readonly #transactions: OpenId4VpTransactionStore
  readonly #results: VerifiedPresentationStore
  readonly #statusChecker: CredentialStatusChecker
  readonly #decryptionKey: CryptoKey
  readonly #encryptionKeyId: string
  readonly #trustedContinuationUri: string
  readonly #clock: () => Date

  constructor(input: {
    transactions: OpenId4VpTransactionStore
    results: VerifiedPresentationStore
    statusChecker: CredentialStatusChecker
    decryptionKey: CryptoKey
    encryptionKeyId: string
    trustedContinuationUri: string
    clock?: () => Date
  }) {
    if (!input.statusChecker || typeof input.statusChecker.check !== 'function' ||
        !input.encryptionKeyId ||
        !validHttps(input.trustedContinuationUri)) {
      throw new Error('Invalid trusted verifier response configuration')
    }
    this.#transactions = input.transactions
    this.#results = input.results
    this.#statusChecker = input.statusChecker
    this.#decryptionKey = input.decryptionKey
    this.#encryptionKeyId = input.encryptionKeyId
    this.#trustedContinuationUri = input.trustedContinuationUri
    this.#clock = input.clock ?? (() => new Date())
  }

  async processForm(formBody: string): Promise<ProcessDirectPostResponseResult> {
    const fail = (reason: string): ProcessDirectPostResponseResult => ({
      status: 'unverifiable', reason,
    })
    if (typeof formBody !== 'string' || formBody.length > MAX_POST_BODY_BYTES) {
      return fail('invalid_http_form')
    }
    const params = new URLSearchParams(formBody)
    if ([...params.keys()].length !== 1 ||
        params.getAll('response').length !== 1) {
      return fail('invalid_http_form')
    }
    const response = params.get('response')
    if (!response || response.length > MAX_POST_BODY_BYTES) {
      return fail('invalid_http_form')
    }
    let decoded: unknown
    try {
      const header = decodeProtectedHeader(response)
      if (header.alg !== 'ECDH-ES' || header.enc !== 'A128GCM' ||
          header.kid !== this.#encryptionKeyId) return fail('untrusted_response_encryption')
      const decrypted = await compactDecrypt(response, this.#decryptionKey, {
        keyManagementAlgorithms: ['ECDH-ES'],
        contentEncryptionAlgorithms: ['A128GCM'],
      })
      decoded = JSON.parse(new TextDecoder().decode(decrypted.plaintext)) as unknown
    } catch {
      return fail('invalid_encrypted_response')
    }

    const payload = record(decoded)
    if (!payload || typeof payload.state !== 'string' ||
        !/^[A-Za-z0-9_-]{40,80}$/.test(payload.state)) {
      return fail('invalid_state')
    }

    // Single-use state consumed *before* checking an untrusted VP; invalid
    // same-transaction replies burn the request. A new request is needed.
    const transaction = await this.#transactions.take(payload.state)
    if (!transaction) return fail('state_not_found_or_replayed')

    const now = this.#clock().getTime()
    if (!Number.isFinite(now) ||
        now < transaction.issuedAt ||
        now >= transaction.expiresAt) return fail('request_expired')

    const vpToken = record(payload.vp_token)
    if (!vpToken ||
        Object.keys(vpToken).length !== 1 ||
        !Array.isArray(vpToken[OID4VP_VC_QUERY_ID]) ||
        vpToken[OID4VP_VC_QUERY_ID].length !== 1 ||
        typeof vpToken[OID4VP_VC_QUERY_ID][0] !== 'string') {
      return fail('invalid_dcql_response_shape')
    }

    const check = await verifyJwtVcJsonPresentation({
      vpJwt: vpToken[OID4VP_VC_QUERY_ID][0],
      tx: transaction,
      statusChecker: this.#statusChecker,
      now: new Date(now),
    })
    if (check.status === 'not_satisfied') {
      return { status: 'not_satisfied', reason: check.reason }
    }
    if (check.status === 'unverifiable') {
      return { status: 'unverifiable', reason: check.reason }
    }

    const code = randomCode()
    await this.#results.save({
      code,
      initiatedBySession: transaction.initiatedBySession,
      expiresAt: Math.min(now + MAX_RESPONSE_CODE_LIFETIME_MS, transaction.expiresAt),
      result: check,
    })
    // Fragment avoids sending the one-time code in the HTTP request URL.
    // The frontend must POST the code to an authenticated same-session route.
    const base = new URL(this.#trustedContinuationUri)
    base.hash = 'response_code=' + encodeURIComponent(code)
    return { status: 'pending_user_confirmation', redirect_uri: base.toString() }
  }

  async confirmFromInitiatingSession(input: {
    responseCode: string
    authenticatedBrowserSession: string
  }): Promise<OnchainAgeVpResult> {
    if (!/^[0-9a-f]{64}$/.test(input.responseCode) ||
        !input.authenticatedBrowserSession.trim()) {
      return { status: 'unverifiable', reason: 'invalid_confirmation' }
    }
    const stored = await this.#results.take(input.responseCode, input.authenticatedBrowserSession)
    if (!stored) return { status: 'unverifiable', reason: 'code_not_found_or_consumed' }
    const now = this.#clock().getTime()
    if (!Number.isFinite(now) || now >= stored.expiresAt) {
      return { status: 'unverifiable', reason: 'confirmation_expired' }
    }
    return stored.result
  }
}
