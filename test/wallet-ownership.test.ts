import { describe, expect, test } from 'vitest'
import { privateKeyToAccount } from 'viem/accounts'

import {
  InMemoryOwnershipChallengeStore,
  createChainAwareMessageSignatureVerifier,
  issueOwnershipChallenge,
  verifyOwnershipProof,
} from '../src/wallet-ownership/index.js'

const HOLDER_PRIVATE_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
const OTHER_PRIVATE_KEY =
  '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'

const holder = privateKeyToAccount(HOLDER_PRIVATE_KEY)
const other = privateKeyToAccount(OTHER_PRIVATE_KEY)
const issuedAt = new Date('2026-11-01T16:00:00.000Z')
const HOLDER_SESSION_ID = 'holder-session-a'

function createStore() {
  return new InMemoryOwnershipChallengeStore()
}

async function issue(store: InMemoryOwnershipChallengeStore) {
  return issueOwnershipChallenge(
    {
      address: holder.address,
      chainId: 1,
      domain: 'reputation.test',
      trustedOrigin: 'https://reputation.test',
      uri: 'https://reputation.test/wallet-link',
      holderSessionId: HOLDER_SESSION_ID,
      now: issuedAt,
      ttlMs: 5 * 60 * 1_000,
    },
    store,
  )
}

function verificationInput(
  challenge: Awaited<ReturnType<typeof issue>>,
  signature: `0x${string}`,
  holderSessionId = HOLDER_SESSION_ID,
) {
  return {
    message: challenge.message,
    signature,
    holderSessionId,
    now: new Date('2026-11-01T16:01:00.000Z'),
  } as const
}

describe('wallet ownership', () => {
  test('accepts a valid SIWE proof for the issued wallet and session', async () => {
    const store = createStore()
    const challenge = await issue(store)
    const signature = await holder.signMessage({ message: challenge.message })

    const result = await verifyOwnershipProof(
      verificationInput(challenge, signature),
      store,
    )

    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.address).toBe(holder.address)
      expect(result.chainId).toBe(1)
    }
  })

  test('rejects replay of an already consumed challenge', async () => {
    const store = createStore()
    const challenge = await issue(store)
    const signature = await holder.signMessage({ message: challenge.message })
    const input = verificationInput(challenge, signature)

    const first = await verifyOwnershipProof(input, store)
    const replay = await verifyOwnershipProof(input, store)

    expect(first.ok).toBe(true)
    expect(replay).toEqual({
      ok: false,
      reason: 'challenge_not_found_or_consumed',
    })
  })

  test('rejects another holder session without consuming the real challenge', async () => {
    const store = createStore()
    const challenge = await issue(store)
    const signature = await holder.signMessage({ message: challenge.message })

    const wrongSession = await verifyOwnershipProof(
      verificationInput(challenge, signature, 'holder-session-b'),
      store,
    )

    expect(wrongSession).toEqual({
      ok: false,
      reason: 'challenge_not_found_or_consumed',
    })

    const legitimateSession = await verifyOwnershipProof(
      verificationInput(challenge, signature),
      store,
    )
    expect(legitimateSession.ok).toBe(true)
  })

  test('rejects a signature from a different wallet', async () => {
    const store = createStore()
    const challenge = await issue(store)
    const signature = await other.signMessage({ message: challenge.message })

    const result = await verifyOwnershipProof(
      verificationInput(challenge, signature),
      store,
    )

    expect(result).toEqual({ ok: false, reason: 'invalid_signature' })
  })

  test('rejects an expired challenge', async () => {
    const store = createStore()
    const challenge = await issueOwnershipChallenge(
      {
        address: holder.address,
        chainId: 1,
        domain: 'reputation.test',
        trustedOrigin: 'https://reputation.test',
        uri: 'https://reputation.test/wallet-link',
        holderSessionId: HOLDER_SESSION_ID,
        now: issuedAt,
        ttlMs: 60_000,
      },
      store,
    )
    const signature = await holder.signMessage({ message: challenge.message })

    const result = await verifyOwnershipProof(
      {
        message: challenge.message,
        signature,
        holderSessionId: HOLDER_SESSION_ID,
        now: new Date('2026-11-01T16:01:00.001Z'),
      },
      store,
    )

    expect(result).toEqual({ ok: false, reason: 'challenge_expired' })
  })

  test('rejects a domain-tampered message even when the holder signs it', async () => {
    const store = createStore()
    const challenge = await issue(store)
    const tamperedMessage = challenge.message.replace(
      'reputation.test wants you to sign in',
      'evil.test wants you to sign in',
    )
    const signature = await holder.signMessage({ message: tamperedMessage })

    const result = await verifyOwnershipProof(
      {
        message: tamperedMessage,
        signature,
        holderSessionId: HOLDER_SESSION_ID,
        now: new Date('2026-11-01T16:01:00.000Z'),
      },
      store,
    )

    expect(result).toEqual({ ok: false, reason: 'message_mismatch' })
  })

  test('rejects malformed input before consuming any unrelated challenge', async () => {
    const store = createStore()
    const challenge = await issue(store)

    const malformed = await verifyOwnershipProof(
      {
        message: 'not a SIWE message',
        signature: '0x00',
        holderSessionId: HOLDER_SESSION_ID,
        now: new Date('2026-11-01T16:01:00.000Z'),
      },
      store,
    )

    expect(malformed).toEqual({ ok: false, reason: 'malformed_message' })

    const signature = await holder.signMessage({ message: challenge.message })
    const valid = await verifyOwnershipProof(
      verificationInput(challenge, signature),
      store,
    )
    expect(valid.ok).toBe(true)
  })

  test('refuses challenge lifetimes longer than the security maximum', async () => {
    const store = createStore()

    await expect(
      issueOwnershipChallenge(
        {
          address: holder.address,
          chainId: 1,
          domain: 'reputation.test',
          trustedOrigin: 'https://reputation.test',
          uri: 'https://reputation.test/wallet-link',
          holderSessionId: HOLDER_SESSION_ID,
          now: issuedAt,
          ttlMs: 10 * 60 * 1_000 + 1,
        },
        store,
      ),
    ).rejects.toThrow('ttlMs must be an integer')
  })

  test('rejects domain and URI not matching trusted origin', async () => {
    const store = createStore()
    const base = {
      address: holder.address,
      chainId: 1,
      holderSessionId: HOLDER_SESSION_ID,
      trustedOrigin: 'https://reputation.test',
      now: issuedAt,
    } as const
    await expect(issueOwnershipChallenge({
      ...base, domain: 'evil.test', uri: 'https://reputation.test/wallet-link',
    }, store)).rejects.toThrow('trusted origin')
    await expect(issueOwnershipChallenge({
      ...base, domain: 'reputation.test', uri: 'https://evil.test/wallet-link',
    }, store)).rejects.toThrow('trusted origin')
    await expect(issueOwnershipChallenge({
      ...base, domain: 'reputation.test', uri: 'http://reputation.test/wallet-link',
    }, store)).rejects.toThrow('trusted origin')
  })

  test('rejects challenge from future beyond allowed clock skew', async () => {
    const store = createStore()
    const challenge = await issue(store)
    const signature = await holder.signMessage({ message: challenge.message })
    const result = await verifyOwnershipProof({
      ...verificationInput(challenge, signature),
      now: new Date(issuedAt.getTime() - 30_001),
    }, store)
    expect(result).toEqual({ ok: false, reason: 'challenge_not_yet_valid' })
  })

  test('at most one concurrent replay attempt can succeed', async () => {
    const store = createStore()
    const challenge = await issue(store)
    const signature = await holder.signMessage({ message: challenge.message })
    const request = verificationInput(challenge, signature)
    const results = await Promise.all([
      verifyOwnershipProof(request, store),
      verifyOwnershipProof(request, store),
    ])
    expect(results.filter(result => result.ok)).toHaveLength(1)
  })

  test('a verifier bound to another chain cannot be used for this wallet', async () => {
    const store = createStore()
    const challenge = await issue(store)
    const signature = await holder.signMessage({ message: challenge.message })
    let calls = 0
    const fakeClient = {
      async verifyMessage() { calls++; return true },
    }
    const verifier = createChainAwareMessageSignatureVerifier(8453, fakeClient)
    const result = await verifyOwnershipProof(
      verificationInput(challenge, signature), store, verifier,
    )
    expect(result).toEqual({ ok: false, reason: 'invalid_signature' })
    expect(calls).toBe(0)
  })

  test('a matching-chain injected verifier receives the exact challenge', async () => {
    const store = createStore()
    const challenge = await issue(store)
    const signature = await holder.signMessage({ message: challenge.message })
    let receivedMessage = ''
    const verifier = createChainAwareMessageSignatureVerifier(1, {
      async verifyMessage({ message }) {
        receivedMessage = message
        return true
      },
    })
    const result = await verifyOwnershipProof(
      verificationInput(challenge, signature), store, verifier,
    )
    expect(result.ok).toBe(true)
    expect(receivedMessage).toBe(challenge.message)
  })
})
