import type { IssuanceSessionStore, PrivateIssuanceSession } from '../issuance/secure-session.js'
import type { OpenId4VpTransaction, OpenId4VpTransactionStore } from '../openid4vp/interop/types.js'
import type { PendingVerifiedPresentation, VerifiedPresentationStore } from '../openid4vp/interop/response.js'

/**
 * Redis >=6.2. Production connector MUST use TLS, auth, least-privilege ACL,
 * no eviction for these keys, bounded timeouts and redacted logs.
 */
export interface RedisAtomicClient {
  sendCommand(command: readonly string[]): Promise<unknown>
}
export type RedisStoreOptions = Readonly<{
  redis: RedisAtomicClient
  namespace: string
  clock?: () => number
}>
const CONSUME_FOR_SESSION = [
  "local value = redis.call('GET', KEYS[1])",
  "if not value then return false end",
  "local ok, item = pcall(cjson.decode, value)",
  "if not ok or type(item) ~= 'table' then return false end",
  "if item.holderSessionId ~= ARGV[1] and item.initiatedBySession ~= ARGV[1] then return false end",
  "redis.call('DEL', KEYS[1])",
  "return value",
].join('\n')
const MAX_TTL = 10 * 60_000

function object(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value)
}

export class RedisAtomicEnvelope {
  readonly #client: RedisAtomicClient
  readonly #prefix: string
  readonly #clock: () => number

  constructor(options: RedisStoreOptions) {
    if (!/^[a-zA-Z0-9:_-]{3,80}$/.test(options.namespace)) {
      throw new Error('Invalid Redis namespace')
    }
    this.#client = options.redis
    this.#prefix = options.namespace
    this.#clock = options.clock ?? (() => Date.now())
  }

  async #key(kind: string, token: string): Promise<string> {
    if (!/^[a-zA-Z0-9_-]{32,128}$/.test(token)) {
      throw new Error('Invalid opaque nonce/state')
    }
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token))
    const hex = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('')
    return this.#prefix + ':' + kind + ':' + hex
  }

  async save(kind: string, token: string, expiresAt: number, record: object): Promise<void> {
    const ttl = Math.floor(expiresAt - this.#clock())
    if (!Number.isSafeInteger(ttl) || ttl < 1 || ttl > MAX_TTL) {
      throw new Error('Invalid nonce lifetime')
    }
    const serialized = JSON.stringify(record)
    if (serialized.length > 8192) throw new Error('Oversized nonce envelope')
    const answer = await this.#client.sendCommand([
      'SET', await this.#key(kind, token), serialized, 'PX', String(ttl), 'NX',
    ])
    if (answer !== 'OK') throw new Error('Atomic store collision or unavailable Redis')
  }

  async take(kind: string, token: string, session?: string): Promise<unknown> {
    const key = await this.#key(kind, token)
    if (session !== undefined && !session.trim()) throw new Error('Session required')
    const answer = session === undefined
      ? await this.#client.sendCommand(['GETDEL', key])
      : await this.#client.sendCommand([
          'EVAL', CONSUME_FOR_SESSION, '1', key, session,
        ])
    if (answer === null || answer === false) return undefined
    if (typeof answer !== 'string' || answer.length > 8192) {
      throw new Error('Corrupt Redis response')
    }
    const decoded: unknown = JSON.parse(answer)
    if (!object(decoded)) throw new Error('Corrupt Redis envelope')
    return decoded
  }
}

/**
 * Stores just trusted server-owned issuance state. Wrong holder session never
 * consumes the challenge, including under concurrent multi-replica requests.
 */
export class RedisIssuanceSessionStore implements IssuanceSessionStore {
  readonly #db: RedisAtomicEnvelope
  constructor(config: RedisStoreOptions) { this.#db = new RedisAtomicEnvelope(config) }

  async save(session: PrivateIssuanceSession): Promise<void> {
    await this.#db.save('issue', session.nonce, Date.parse(session.expiresAt), {
      ...session,
      verifiedOwnership: {
        ...session.verifiedOwnership,
        verifiedAt: session.verifiedOwnership.verifiedAt.toISOString(),
      },
    })
  }

  async take(nonce: string, holderSessionId: string): Promise<PrivateIssuanceSession | undefined> {
    const value = await this.#db.take('issue', nonce, holderSessionId)
    if (value === undefined) return undefined
    if (!object(value) || !object(value.verifiedOwnership) ||
        value.nonce !== nonce || value.holderSessionId !== holderSessionId ||
        typeof value.audience !== 'string' || typeof value.issuedAt !== 'string' ||
        typeof value.expiresAt !== 'string' || typeof value.thresholdDate !== 'string' ||
        value.verifiedOwnership.ok !== true ||
        typeof value.verifiedOwnership.address !== 'string' ||
        typeof value.verifiedOwnership.chainId !== 'number' ||
        typeof value.verifiedOwnership.verifiedAt !== 'string' ||
        !Number.isFinite(Date.parse(value.verifiedOwnership.verifiedAt))) {
      throw new Error('Corrupt issuance session')
    }
    return {
      nonce,
      holderSessionId,
      audience: value.audience,
      issuedAt: value.issuedAt,
      expiresAt: value.expiresAt,
      thresholdDate: value.thresholdDate,
      verifiedOwnership: {
        ok: true,
        address: value.verifiedOwnership.address as PrivateIssuanceSession['verifiedOwnership']['address'],
        chainId: value.verifiedOwnership.chainId,
        verifiedAt: new Date(value.verifiedOwnership.verifiedAt),
      },
    }
  }
}

export class RedisVerifiedPresentationStore implements VerifiedPresentationStore {
  readonly #db: RedisAtomicEnvelope
  constructor(config: RedisStoreOptions) { this.#db = new RedisAtomicEnvelope(config) }

  async save(value: PendingVerifiedPresentation): Promise<void> {
    await this.#db.save('confirm', value.code, value.expiresAt, value)
  }

  async take(code: string, initiatedBySession: string): Promise<PendingVerifiedPresentation | undefined> {
    const value = await this.#db.take('confirm', code, initiatedBySession)
    if (value === undefined) return undefined
    if (!object(value) || value.code !== code ||
        value.initiatedBySession !== initiatedBySession ||
        typeof value.expiresAt !== 'number' ||
        !object(value.result) || value.result.status !== 'satisfied' ||
        typeof value.result.chainId !== 'number' ||
        !Number.isSafeInteger(value.result.chainId) ||
        typeof value.result.thresholdDate !== 'string') {
      throw new Error('Corrupt verified presentation')
    }
    return {
      code, initiatedBySession, expiresAt: value.expiresAt,
      result: {
        status: 'satisfied',
        chainId: value.result.chainId,
        thresholdDate: value.result.thresholdDate,
      },
    }
  }
}

/** Key registry is trusted server config; NEVER loaded from untrusted Redis. */
export type TrustedIssuerKeyResolver = (
  issuer: string, kid: string,
) => Promise<CryptoKey | undefined> | CryptoKey | undefined

/**
 * JSON cannot safely serialize a CryptoKey. Only issuer + kid are persisted;
 * the pinned issuer public key is resolved from a server-controlled registry.
 */
export class RedisOpenId4VpTransactionStore implements OpenId4VpTransactionStore {
  readonly #db: RedisAtomicEnvelope
  readonly #resolve: TrustedIssuerKeyResolver
  constructor(options: RedisStoreOptions & { resolveIssuerKey: TrustedIssuerKeyResolver }) {
    this.#db = new RedisAtomicEnvelope(options)
    this.#resolve = options.resolveIssuerKey
  }

  async save(tx: OpenId4VpTransaction): Promise<void> {
    const { issuerPublicKey: _key, ...serializablePolicy } = tx.policy
    if (tx.format !== 'jwt_vc_json' && tx.format !== 'dc+sd-jwt') {
      throw new Error('VP credential format must be explicitly pinned')
    }
    await this.#db.save('vp', tx.state, tx.expiresAt, {
      ...tx,
      policy: serializablePolicy,
    })
  }

  async take(state: string): Promise<OpenId4VpTransaction | undefined> {
    const v = await this.#db.take('vp', state)
    if (v === undefined) return undefined
    if (!object(v) || !object(v.policy) ||
        v.state !== state || typeof v.nonce !== 'string' ||
        typeof v.clientId !== 'string' || typeof v.responseUri !== 'string' ||
        typeof v.initiatedBySession !== 'string' ||
        typeof v.issuedAt !== 'number' || typeof v.expiresAt !== 'number' ||
        typeof v.policy.issuer !== 'string' ||
        typeof v.policy.issuerKeyId !== 'string' ||
        typeof v.policy.chainId !== 'number' ||
        typeof v.policy.methodologyVersion !== 'string' ||
        typeof v.policy.requiredThresholdDate !== 'string' ||
        (v.format !== 'jwt_vc_json' && v.format !== 'dc+sd-jwt')) {
      throw new Error('Corrupt VP transaction')
    }
    const key = await this.#resolve(v.policy.issuer, v.policy.issuerKeyId)
    if (!key) throw new Error('Pinned issuer key unavailable')
    return {
      state,
      nonce: v.nonce, clientId: v.clientId, responseUri: v.responseUri,
      initiatedBySession: v.initiatedBySession,
      issuedAt: v.issuedAt, expiresAt: v.expiresAt,
      ...(v.format === 'dc+sd-jwt' ? { format: 'dc+sd-jwt' as const } :
        v.format === 'jwt_vc_json' ? { format: 'jwt_vc_json' as const } : {}),
      policy: {
        issuer: v.policy.issuer,
        issuerKeyId: v.policy.issuerKeyId,
        issuerPublicKey: key,
        chainId: v.policy.chainId,
        methodologyVersion: v.policy.methodologyVersion,
        requiredThresholdDate: v.policy.requiredThresholdDate,
      },
    }
  }
}
