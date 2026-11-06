import { describe, expect, test } from 'vitest'
import { generateKeyPair } from 'jose'
import {
  RedisAtomicEnvelope,
  RedisIssuanceSessionStore,
  RedisOpenId4VpTransactionStore,
  RedisVerifiedPresentationStore,
  type RedisAtomicClient,
  type RedisStoreOptions,
} from '../src/storage/redis-atomic.js'

const NOW = Date.parse('2026-11-06T20:00:00.000Z')
const NONCE = 'a'.repeat(43)
const STATE = 'b'.repeat(43)
const CODE = 'c'.repeat(64)
const WALLET = '0x00000000000000000000000000000000000000A1'
const encryptionKey = await crypto.subtle.generateKey(
  { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
)
const sessionBindingKey = await crypto.subtle.generateKey(
  { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign'],
)

/**
 * Deterministic in-process Redis *command model*, not a live Redis server
 * certification. Commands are serialized at each sendCommand call to model
 * Redis atomic command and Lua script semantics.
 */
class FakeRedis implements RedisAtomicClient {
  readonly values = new Map<string, { value: string; until: number }>()
  readonly history: string[][] = []
  down = false
  clock = NOW
  async sendCommand(command: readonly string[]): Promise<unknown> {
    this.history.push([...command])
    if (this.down) throw new Error('Redis network unavailable')
    const [op, key] = command
    if (op === 'SET') {
      const old = this.values.get(key!)
      if (old && old.until > this.clock) return null
      const ttl = Number(command[4])
      this.values.set(key!, { value: command[2]!, until: this.clock + ttl })
      return 'OK'
    }
    if (op === 'GETDEL') {
      const old = this.values.get(key!)
      if (!old || old.until <= this.clock) return null
      this.values.delete(key!)
      return old.value
    }
    if (op === 'EVAL') {
      const redisKey = command[3]!
      const entry = this.values.get(redisKey)
      if (!entry || entry.until <= this.clock) return null
      const item = JSON.parse(entry.value) as Record<string, unknown>
      if (item.sessionBinding !== command[4]) return null
      this.values.delete(redisKey)
      return entry.value
    }
    throw new Error('Unexpected Redis command ' + op)
  }
}

function config(client: FakeRedis): RedisStoreOptions {
  return {
    redis: client,
    namespace: 'reputation:test',
    encryptionKey,
    sessionBindingKey,
    clock: () => client.clock,
  }
}

function issuance() {
  return {
    nonce: NONCE,
    audience: 'https://issuer.example',
    holderSessionId: 'session-A',
    issuedAt: new Date(NOW).toISOString(),
    expiresAt: new Date(NOW + 120_000).toISOString(),
    thresholdDate: new Date(NOW - 365 * 24 * 60 * 60_000).toISOString(),
    verifiedOwnership: {
      ok: true as const,
      chainId: 1,
      address: WALLET as `0x${string}`,
      verifiedAt: new Date(NOW - 60_000),
    },
  }
}

describe('Redis distributed atomic adapter command contracts', () => {
  test('SET PX NX prevents nonce overwrite and does not expose nonce as Redis key', async () => {
    const redis = new FakeRedis()
    const store = new RedisIssuanceSessionStore(config(redis))
    await store.save(issuance())
    const set = redis.history[0]!
    expect(set[0]).toBe('SET')
    expect(set[3]).toBe('PX')
    expect(set[5]).toBe('NX')
    expect(set[1]).not.toContain(NONCE)
    expect(set[1]).toMatch(/^reputation:test:issue:[a-f0-9]{64}$/)
    expect(set[2]).not.toContain(WALLET)
    expect(set[2]).not.toContain('session-A')
    expect(set[2]).toContain('ciphertext')
    await expect(store.save(issuance())).rejects.toThrow('Atomic store collision')
  })

  test('wrong session leaves valid nonce for original session, including across store replicas', async () => {
    const redis = new FakeRedis()
    const a = new RedisIssuanceSessionStore(config(redis))
    const b = new RedisIssuanceSessionStore(config(redis))
    await a.save(issuance())
    expect(await b.take(NONCE, 'session-attacker')).toBeUndefined()
    const valid = await a.take(NONCE, 'session-A')
    expect(valid?.verifiedOwnership.address).toBe(WALLET)
    expect(valid?.verifiedOwnership.verifiedAt).toBeInstanceOf(Date)
    expect(valid?.verifiedOwnership.verifiedAt.getTime()).toBe(NOW - 60_000)
    expect(await b.take(NONCE, 'session-A')).toBeUndefined()
  })

  test('concurrent cross-instance consumption succeeds at most once', async () => {
    const redis = new FakeRedis()
    const a = new RedisIssuanceSessionStore(config(redis))
    const b = new RedisIssuanceSessionStore(config(redis))
    await a.save(issuance())
    const results = await Promise.all([
      a.take(NONCE, 'session-A'),
      b.take(NONCE, 'session-A'),
      b.take(NONCE, 'session-A'),
    ])
    expect(results.filter(Boolean)).toHaveLength(1)
  })

  test('TTL expiry, oversized TTL and Redis outage fail closed', async () => {
    const redis = new FakeRedis()
    const store = new RedisIssuanceSessionStore(config(redis))
    await store.save(issuance())
    redis.clock += 120_000
    expect(await store.take(NONCE, 'session-A')).toBeUndefined()
    await expect(new RedisAtomicEnvelope(config(redis)).save(
      'issue', NONCE, redis.clock + 11 * 60_000, {},
    )).rejects.toThrow('lifetime')
    redis.down = true
    await expect(store.take(NONCE, 'session-A')).rejects.toThrow('network unavailable')
  })

  test('one-time confirmation code is session-bound and consumed across replicas', async () => {
    const redis = new FakeRedis()
    const a = new RedisVerifiedPresentationStore(config(redis))
    const b = new RedisVerifiedPresentationStore(config(redis))
    await a.save({
      code: CODE,
      initiatedBySession: 'browser-A',
      expiresAt: NOW + 90_000,
      result: { status: 'satisfied', chainId: 1, thresholdDate: '2024-01-01T00:00:00.000Z' },
    })
    expect(await b.take(CODE, 'browser-B')).toBeUndefined()
    expect((await a.take(CODE, 'browser-A'))?.result.status).toBe('satisfied')
    expect(await b.take(CODE, 'browser-A')).toBeUndefined()
  })

  test('public-key material is rehydrated from trusted server registry, never stored as JSON', async () => {
    const redis = new FakeRedis()
    const keyPair = await generateKeyPair('ES256', { extractable: true })
    const called: string[] = []
    const resolver = (issuer: string, kid: string) => {
      called.push(issuer + '#' + kid)
      return issuer === 'https://issuer.example' && kid === 'issuer-kid' ? keyPair.publicKey : undefined
    }
    const a = new RedisOpenId4VpTransactionStore({ ...config(redis), resolveIssuerKey: resolver })
    const b = new RedisOpenId4VpTransactionStore({ ...config(redis), resolveIssuerKey: resolver })
    await a.save({
      state: STATE,
      format: 'jwt_vc_json',
      nonce: NONCE,
      clientId: 'verifier_attestation:verifier.example',
      responseUri: 'https://verifier.example/response',
      initiatedBySession: 'browser-A',
      issuedAt: NOW,
      expiresAt: NOW + 100_000,
      policy: {
        issuer: 'https://issuer.example',
        issuerKeyId: 'issuer-kid',
        issuerPublicKey: keyPair.publicKey,
        chainId: 1,
        methodologyVersion: 'onchain-age/0.1.0',
        requiredThresholdDate: '2024-01-01T00:00:00.000Z',
      },
    })
    const savedValue = [...redis.values.values()][0]!.value
    expect(savedValue).not.toContain('issuerPublicKey')
    expect(called).toHaveLength(0)
    const roundtrip = await b.take(STATE)
    expect(roundtrip?.policy.issuerPublicKey).toBe(keyPair.publicKey)
    expect(called).toEqual(['https://issuer.example#issuer-kid'])
    expect(await a.take(STATE)).toBeUndefined()
  })

  test('unresolvable issuer key fails closed after atomic state consumption', async () => {
    const redis = new FakeRedis()
    const keyPair = await generateKeyPair('ES256')
    const store = new RedisOpenId4VpTransactionStore({
      ...config(redis), resolveIssuerKey: () => undefined,
    })
    await store.save({
      state: STATE, format: 'jwt_vc_json', nonce: NONCE,
      clientId: 'verifier_attestation:verifier.example',
      responseUri: 'https://verifier.example/response',
      initiatedBySession: 'browser-A',
      issuedAt: NOW, expiresAt: NOW + 100_000,
      policy: {
        issuer: 'https://issuer.example', issuerKeyId: 'unknown',
        issuerPublicKey: keyPair.publicKey, chainId: 1,
        methodologyVersion: 'onchain-age/0.1.0',
        requiredThresholdDate: '2024-01-01T00:00:00.000Z',
      },
    })
    await expect(store.take(STATE)).rejects.toThrow('Pinned issuer key unavailable')
    expect(await store.take(STATE)).toBeUndefined()
  })


  test('does not persist a VP request without an explicit trusted credential format', async () => {
    const redis = new FakeRedis()
    const store = new RedisOpenId4VpTransactionStore({
      ...config(redis), resolveIssuerKey: () => undefined,
    })
    const key = (await generateKeyPair('ES256')).publicKey
    await expect(store.save({
      state: STATE,
      nonce: NONCE,
      clientId: 'verifier_attestation:verifier.example',
      responseUri: 'https://verifier.example/response',
      initiatedBySession: 'browser-A',
      issuedAt: NOW,
      expiresAt: NOW + 90_000,
      policy: {
        issuer: 'https://issuer.example',
        issuerKeyId: 'key1',
        issuerPublicKey: key,
        chainId: 1,
        methodologyVersion: 'onchain-age/0.1.0',
        requiredThresholdDate: '2024-01-01T00:00:00.000Z',
      },
    })).rejects.toThrow('explicitly pinned')
    expect(redis.values.size).toBe(0)
  })

  test('modifying AES-GCM ciphertext fails closed and consumes the tampered nonce', async () => {
    const redis = new FakeRedis()
    const store = new RedisIssuanceSessionStore(config(redis))
    await store.save(issuance())
    const [key, entry] = [...redis.values.entries()][0]!
    const envelope = JSON.parse(entry.value) as { v: number; ciphertext: string; iv: string; sessionBinding: string }
    const first = envelope.ciphertext[0]!
    envelope.ciphertext = (first === 'A' ? 'B' : 'A') + envelope.ciphertext.slice(1)
    redis.values.set(key, { ...entry, value: JSON.stringify(envelope) })
    await expect(store.take(NONCE, 'session-A')).rejects.toThrow('authentication failed')
    expect(await store.take(NONCE, 'session-A')).toBeUndefined()
  })

  test('binding tag cannot be reused across a different nonce', async () => {
    const redis = new FakeRedis()
    const db = new RedisAtomicEnvelope(config(redis))
    await db.save('vp', NONCE, NOW + 60_000, { holderSessionId: 'session-A', payload: 'sensitive' })
    const record = [...redis.values.values()][0]!.value
    const stored = JSON.parse(record) as { sessionBinding: string; ciphertext: string }
    expect(stored.sessionBinding).not.toContain('session-A')
    expect(stored.ciphertext).not.toContain('sensitive')
    expect(await db.take('vp', 'z'.repeat(43), 'session-A')).toBeUndefined()
    expect(await db.take('vp', NONCE, 'session-A')).toEqual({
      holderSessionId: 'session-A', payload: 'sensitive',
    })
  })

  test('Redis namespace and opaque identifiers are validated before network access', async () => {
    const redis = new FakeRedis()
    expect(() => new RedisAtomicEnvelope({ ...config(redis), namespace: 'invalid prefix' }))
      .toThrow('namespace')
    await expect(new RedisAtomicEnvelope(config(redis)).take('vp', '../raw-token'))
      .rejects.toThrow('nonce/state')
    expect(redis.history).toHaveLength(0)
  })
})
