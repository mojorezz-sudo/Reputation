import { describe, expect, test } from 'vitest'
import { privateKeyToAccount } from 'viem/accounts'

import {
  InMemoryOwnershipChallengeStore,
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

function createStore() {
  return new InMemoryOwnershipChallengeStore()
}

async function issue(store: InMemoryOwnershipChallengeStore) {
  return issueOwnershipChallenge(
    {
      address: holder.address,
      chainId: 1,
      domain: 'reputation.test',
      uri: 'https://reputation.test/wallet-link',
      now: issuedAt,
      ttlMs: 5 * 60 * 1_000,
    },
    store,
  )
}

describe('wallet ownership', () => {
  test('accepts a valid SIWE proof for the issued wallet', async () => {
    const store = createStore()
    const challenge = await issue(store)
    const signature = await holder.signMessage({ message: challenge.message })

    const result = await verifyOwnershipProof(
      {
        message: challenge.message,
        signature,
        now: new Date('2026-11-01T16:01:00.000Z'),
      },
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
    const now = new Date('2026-11-01T16:01:00.000Z')

    const first = await verifyOwnershipProof(
      { message: challenge.message, signature, now },
      store,
    )
    const replay = await verifyOwnershipProof(
      { message: challenge.message, signature, now },
      store,
    )

    expect(first.ok).toBe(true)
    expect(replay).toEqual({
      ok: false,
      reason: 'challenge_not_found_or_consumed',
    })
  })

  test('rejects a signature from a different wallet', async () => {
    const store = createStore()
    const challenge = await issue(store)
    const signature = await other.signMessage({ message: challenge.message })

    const result = await verifyOwnershipProof(
      {
        message: challenge.message,
        signature,
        now: new Date('2026-11-01T16:01:00.000Z'),
      },
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
        uri: 'https://reputation.test/wallet-link',
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
        now: new Date('2026-11-01T16:01:00.000Z'),
      },
      store,
    )

    expect(malformed).toEqual({ ok: false, reason: 'malformed_message' })

    const signature = await holder.signMessage({ message: challenge.message })
    const valid = await verifyOwnershipProof(
      {
        message: challenge.message,
        signature,
        now: new Date('2026-11-01T16:01:00.000Z'),
      },
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
          uri: 'https://reputation.test/wallet-link',
          now: issuedAt,
          ttlMs: 10 * 60 * 1_000 + 1,
        },
        store,
      ),
    ).rejects.toThrow('ttlMs must be an integer')
  })
})
