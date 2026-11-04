import {
  base64url,
  decodeProtectedHeader,
  exportJWK,
  importJWK,
  jwtVerify,
  SignJWT,
  type JWK,
} from 'jose'
import { createOnchainAgeDcql, matchesSupportedOnchainAgeDcql } from './query.js'
import {
  OID4VP_ATTESTATION_TYPE,
  OID4VP_REQUEST_TYPE,
  OID4VP_STATIC_WALLET_AUDIENCE,
  type OpenId4VpRequestObject,
  type OpenId4VpTransaction,
  type OpenId4VpTransactionStore,
  type TrustedOnchainAgePolicy,
} from './types.js'

const REQUEST_TTL_MS = 5 * 60_000
const MAX_REQUEST_JWT_LENGTH = 20_000
const VERIFIED_ID_PREFIX = 'verifier_attestation:'

function randomToken(): string {
  return base64url.encode(crypto.getRandomValues(new Uint8Array(32)))
}

function validHttps(uri: string): boolean {
  try {
    const url = new URL(uri)
    return url.protocol === 'https:' && !url.username && !url.password && !url.hash
  } catch {
    return false
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function publicP256Jwk(value: unknown): value is JWK {
  return isRecord(value) && value.kty === 'EC' && value.crv === 'P-256' &&
    typeof value.x === 'string' && typeof value.y === 'string' &&
    value.d === undefined && value.k === undefined
}

export class InMemoryOpenId4VpTransactionStore implements OpenId4VpTransactionStore {
  readonly #pending = new Map<string, OpenId4VpTransaction>()
  async save(transaction: OpenId4VpTransaction): Promise<void> {
    if (this.#pending.has(transaction.state)) throw new Error('State collision')
    this.#pending.set(transaction.state, transaction)
  }
  async take(state: string): Promise<OpenId4VpTransaction | undefined> {
    const tx = this.#pending.get(state)
    if (tx) this.#pending.delete(state)
    return tx
  }
}

/**
 * A trust-framework authority's attestation. In tests the authority is local;
 * a production Wallet MUST obtain and validate an independent trust anchor.
 */
export async function issueTestVerifierAttestation(input: {
  attestorIssuer: string
  attestorPrivateKey: CryptoKey
  /** Full client_id in the attestation sub, per §12; check wallet support. */
  clientId: string
  verifierPublicKey: CryptoKey
  allowedResponseUris: readonly string[]
  now: Date
  validityMs?: number
}): Promise<string> {
  if (!input.clientId.startsWith(VERIFIED_ID_PREFIX) ||
      !validHttps(input.attestorIssuer) ||
      !input.allowedResponseUris.length ||
      input.allowedResponseUris.some(uri => !validHttps(uri))) {
    throw new Error('Invalid verifier attestation policy')
  }
  const jwk = await exportJWK(input.verifierPublicKey)
  if (!publicP256Jwk(jwk)) throw new Error('Expected P-256 verifier key')
  const at = Math.floor(input.now.getTime() / 1000)
  const validity = input.validityMs ?? 60 * 60_000
  if (!Number.isFinite(at) || !Number.isSafeInteger(validity) ||
      validity < 1_000 || validity > 24 * 60 * 60_000) throw new Error('Invalid attestation expiry')
  return new SignJWT({
    cnf: { jwk },
    redirect_uris: [...input.allowedResponseUris],
  })
    .setProtectedHeader({ alg: 'ES256', typ: OID4VP_ATTESTATION_TYPE })
    .setIssuer(input.attestorIssuer)
    .setSubject(input.clientId)
    .setIssuedAt(at)
    .setExpirationTime(Math.floor((input.now.getTime() + validity) / 1000))
    .sign(input.attestorPrivateKey)
}

export type IssuedOpenId4VpRequest = Readonly<{
  request: OpenId4VpRequestObject
  requestObjectJwt: string
  state: string
  nonce: string
  expiresAt: number
}>

/**
 * Real OpenID4VP 1.0 signed Request Object (JAR), using a verifier attestation
 * as the verifier trust mechanism. The wallet-facing attestation is NOT
 * interchangeable with an untrusted client_metadata.jwks entry.
 *
 * When deployed, serve requestObjectJwt under HTTPS request_uri as
 * application/oauth-authz-req+jwt with Cache-Control: no-store.
 */
export async function createAttestedOpenId4VpRequest(input: {
  clientId: string
  responseUri: string
  verifierAttestationJwt: string
  verifierSigningPrivateKey: CryptoKey
  responseEncryptionPublicJwk: JWK
  initiatedBySession: string
  policy: TrustedOnchainAgePolicy
  store: OpenId4VpTransactionStore
  now?: Date
}): Promise<IssuedOpenId4VpRequest> {
  if (!input.clientId.startsWith(VERIFIED_ID_PREFIX) ||
      !input.clientId.slice(VERIFIED_ID_PREFIX.length).trim() ||
      !validHttps(input.responseUri) ||
      !input.initiatedBySession.trim() ||
      !publicP256Jwk(input.responseEncryptionPublicJwk) ||
      typeof input.responseEncryptionPublicJwk.kid !== 'string' ||
      !input.responseEncryptionPublicJwk.kid) {
    throw new Error('Invalid verifier configuration')
  }
  if (input.policy.chainId !== 1 || !input.policy.issuer.trim() ||
      !input.policy.issuerKeyId.trim() || !input.policy.methodologyVersion.trim() ||
      !Number.isFinite(Date.parse(input.policy.requiredThresholdDate))) {
    throw new Error('Invalid OnchainAge verifier policy')
  }

  const now = input.now ?? new Date()
  const nowMs = now.getTime()
  if (!Number.isFinite(nowMs)) throw new Error('Invalid request clock')
  const nonce = randomToken()
  const state = randomToken()
  const request: OpenId4VpRequestObject = {
    client_id: input.clientId,
    response_type: 'vp_token',
    response_mode: 'direct_post.jwt',
    response_uri: input.responseUri,
    nonce,
    state,
    dcql_query: createOnchainAgeDcql(),
    client_metadata: {
      vp_formats_supported: { jwt_vc_json: { alg_values: ['ES256'] } },
      encrypted_response_enc_values_supported: ['A128GCM'],
      jwks: { keys: [input.responseEncryptionPublicJwk] },
    },
  }
  const expiresAt = nowMs + REQUEST_TTL_MS
  // Persist before publishing the request.
  await input.store.save({
    state,
    nonce,
    clientId: input.clientId,
    responseUri: input.responseUri,
    initiatedBySession: input.initiatedBySession,
    issuedAt: nowMs,
    expiresAt,
    policy: input.policy,
  })

  const requestObjectJwt = await new SignJWT(request)
    .setProtectedHeader({
      typ: OID4VP_REQUEST_TYPE,
      alg: 'ES256',
      jwt: input.verifierAttestationJwt,
    })
    .setAudience(OID4VP_STATIC_WALLET_AUDIENCE)
    .setIssuedAt(Math.floor(nowMs / 1000))
    .setExpirationTime(Math.floor(expiresAt / 1000))
    .sign(input.verifierSigningPrivateKey)

  return { request, requestObjectJwt, state, nonce, expiresAt }
}

/**
 * Independent Wallet-side reference verifier. It trusts only its configured
 * attestation authority key, then verifies the nested request with the
 * verifier key from the *verified* attestation. It is not a general wallet SDK.
 */
export async function verifyAttestedRequestForWallet(input: {
  requestObjectJwt: string
  trustedAttestorIssuer: string
  trustedAttestorPublicKey: CryptoKey
  now?: Date
}): Promise<OpenId4VpRequestObject> {
  if (input.requestObjectJwt.length > MAX_REQUEST_JWT_LENGTH) throw new Error('Request object too large')
  const now = input.now ?? new Date()
  const h = decodeProtectedHeader(input.requestObjectJwt)
  if (h.typ !== OID4VP_REQUEST_TYPE || h.alg !== 'ES256' || typeof h.jwt !== 'string') {
    throw new Error('Invalid signed Request Object header')
  }
  const attestation = await jwtVerify(h.jwt, input.trustedAttestorPublicKey, {
    issuer: input.trustedAttestorIssuer,
    typ: OID4VP_ATTESTATION_TYPE,
    algorithms: ['ES256'],
    currentDate: now,
  })
  if (attestation.protectedHeader.alg !== 'ES256' ||
      typeof attestation.payload.sub !== 'string' ||
      !attestation.payload.sub.startsWith(VERIFIED_ID_PREFIX)) {
    throw new Error('Invalid verifier attestation')
  }
  const cnf = isRecord(attestation.payload.cnf) ? attestation.payload.cnf : undefined
  if (!publicP256Jwk(cnf?.jwk)) throw new Error('Verifier attestation lacks trusted public key')
  const key = await importJWK(cnf.jwk, 'ES256')
  const verified = await jwtVerify(input.requestObjectJwt, key, {
    audience: OID4VP_STATIC_WALLET_AUDIENCE,
    typ: OID4VP_REQUEST_TYPE,
    algorithms: ['ES256'],
    currentDate: now,
  })
  const p = verified.payload
  const allowed = attestation.payload.redirect_uris
  if (
    p.client_id !== attestation.payload.sub ||
    typeof p.client_id !== 'string' ||
    p.response_type !== 'vp_token' ||
    p.response_mode !== 'direct_post.jwt' ||
    typeof p.response_uri !== 'string' ||
    !validHttps(p.response_uri) ||
    !Array.isArray(allowed) ||
    !allowed.includes(p.response_uri) ||
    !isRecord(p.client_metadata) ||
    !isRecord(p.client_metadata.vp_formats_supported) ||
    !isRecord(p.client_metadata.jwks) ||
    !matchesSupportedOnchainAgeDcql(p.dcql_query) ||
    typeof p.nonce !== 'string' ||
    !/^[A-Za-z0-9_-]{40,80}$/.test(p.nonce) ||
    typeof p.state !== 'string' ||
    !/^[A-Za-z0-9_-]{40,80}$/.test(p.state)
  ) throw new Error('Invalid OpenID4VP Request Object')
  const keys = p.client_metadata.jwks.keys
  if (!Array.isArray(keys) || keys.length !== 1 ||
      !publicP256Jwk(keys[0]) ||
      typeof keys[0].kid !== 'string' ||
      !keys[0].kid ||
      !isRecord(p.client_metadata.vp_formats_supported.jwt_vc_json) ||
      JSON.stringify(p.client_metadata.vp_formats_supported.jwt_vc_json.alg_values) !== '["ES256"]' ||
      JSON.stringify(p.client_metadata.encrypted_response_enc_values_supported) !== '["A128GCM"]') {
    throw new Error('Invalid OpenID4VP wallet-facing metadata')
  }
  return p as unknown as OpenId4VpRequestObject
}

/** Explicitly HTTPS by-reference, no hard-coded wallet vendor. */
export function buildOpenId4VpInvocationUri(input: {
  walletAuthorizationEndpoint: string
  clientId: string
  requestUri: string
}): string {
  if (!validHttps(input.requestUri) || !validHttps(input.walletAuthorizationEndpoint) ||
      !input.clientId.startsWith(VERIFIED_ID_PREFIX)) {
    throw new Error('Wallet endpoint, request_uri and client_id require trusted configuration')
  }
  const url = new URL(input.walletAuthorizationEndpoint)
  url.searchParams.set('client_id', input.clientId)
  url.searchParams.set('request_uri', input.requestUri)
  return url.toString()
}
