import { describe, expect, test, vi } from 'vitest'
import type { Address, Hex } from 'viem'

import {
  evaluateOnchainAge,
  evaluateOnchainAgeScan,
  type ChainActivityScan,
  type ChainHistoryProvider,
  type ChainSnapshot,
  type NormalizedActivity,
} from '../src/onchain-age/index.js'

const SUBJECT: Address = '0x000000000000000000000000000000000000dEaD'
const OTHER: Address = '0x000000000000000000000000000000000000bEEF'
const HASH: Hex = ('0x' + 'a'.repeat(64)) as Hex
const OTHER_HASH: Hex = ('0x' + 'b'.repeat(64)) as Hex
const SNAPSHOT: ChainSnapshot = {
  chainId: 1,
  blockNumber: 500n,
  blockHash: HASH,
  timestamp: 2_000_000_000,
  finality: 'finalized',
}
const THRESHOLD = 1_500_000_000

const oldOutgoing: NormalizedActivity = {
  kind: 'transaction',
  hash: OTHER_HASH,
  from: SUBJECT,
  blockNumber: 100n,
  blockHash: OTHER_HASH,
  timestamp: 1_400_000_000,
  executionStatus: 'success',
}
const inbound: NormalizedActivity = {
  ...oldOutgoing,
  from: OTHER,
}
const spamToken: NormalizedActivity = {
  kind: 'token_transfer',
  transactionHash: OTHER_HASH,
  from: OTHER,
  to: SUBJECT,
  blockNumber: 100n,
  blockHash: OTHER_HASH,
  timestamp: 1_400_000_000,
}

function makeScan(
  activities: readonly NormalizedActivity[],
  options: {
    fromBlock?: bigint
    toBlock?: bigint
    complete?: boolean
    snapshot?: ChainSnapshot
    subjectAddress?: Address
  } = {},
): ChainActivityScan {
  return {
    chainId: 1,
    subjectAddress: options.subjectAddress ?? SUBJECT,
    providerId: 'fixture-provider',
    adapterVersion: 'fixture/1',
    snapshot: options.snapshot ?? SNAPSHOT,
    coverage: {
      fromBlock: options.fromBlock ?? 0n,
      toBlock: options.toBlock ?? SNAPSHOT.blockNumber,
      complete: options.complete ?? true,
    },
    activities,
  }
}

function makeProvider(scan: ChainActivityScan): ChainHistoryProvider {
  return {
    id: 'fixture-provider',
    adapterVersion: 'fixture/1',
    readActivity: vi.fn(async () => scan),
  }
}

function makeInput(snapshot = SNAPSHOT) {
  return {
    subjectAddress: SUBJECT,
    chainId: 1,
    snapshot,
    thresholdTimestamp: THRESHOLD,
    evaluatedAt: 2_000_000_100,
  } as const
}

describe('OnchainAge v0.1', () => {
  test('accepts an old successful holder-initiated transaction', async () => {
    const result = await evaluateOnchainAge(makeInput(), makeProvider(makeScan([oldOutgoing])))
    expect(result.status).toBe('satisfied')
    expect(result.reason).toBe('qualifying_activity_found')
    expect(result.methodology).toBe('onchain-age/0.1')
    expect(result.asOfBlockHash).toBe(HASH)
    expect(result.providerId).toBe('fixture-provider')
  })

  test('positive evidence needs no claim of complete prehistory', async () => {
    const result = await evaluateOnchainAge(
      makeInput(),
      makeProvider(makeScan([oldOutgoing], { fromBlock: 50n, complete: false })),
    )
    expect(result.status).toBe('satisfied')
  })

  test('incoming dust alone cannot establish age', async () => {
    const result = await evaluateOnchainAge(makeInput(), makeProvider(makeScan([inbound])))
    expect(result).toMatchObject({
      status: 'not_satisfied',
      reason: 'no_qualifying_activity_in_complete_history',
    })
  })

  test('spam token receipt alone cannot establish age', async () => {
    const result = await evaluateOnchainAge(makeInput(), makeProvider(makeScan([spamToken])))
    expect(result.status).toBe('not_satisfied')
  })

  test('failed outbound transaction does not establish age', async () => {
    const failed = { ...oldOutgoing, executionStatus: 'failed' as const }
    const result = await evaluateOnchainAge(makeInput(), makeProvider(makeScan([failed])))
    expect(result.status).toBe('not_satisfied')
  })

  test('unknown execution status does not count as successful evidence', async () => {
    const unknown = { ...oldOutgoing, executionStatus: 'unknown' as const }
    const result = await evaluateOnchainAge(makeInput(), makeProvider(makeScan([unknown])))
    expect(result.status).toBe('not_satisfied')
  })

  test('activity after threshold is not old enough', async () => {
    const recent = { ...oldOutgoing, timestamp: THRESHOLD + 1 }
    const result = await evaluateOnchainAge(makeInput(), makeProvider(makeScan([recent])))
    expect(result.status).toBe('not_satisfied')
  })

  test('activity exactly on threshold qualifies', async () => {
    const boundary = { ...oldOutgoing, timestamp: THRESHOLD }
    const result = await evaluateOnchainAge(makeInput(), makeProvider(makeScan([boundary])))
    expect(result.status).toBe('satisfied')
  })

  test('no evidence under partial coverage is unverifiable, never negative', async () => {
    const result = await evaluateOnchainAge(
      makeInput(),
      makeProvider(makeScan([], { fromBlock: 200n, complete: false })),
    )
    expect(result).toMatchObject({ status: 'unverifiable', reason: 'incomplete_history' })
  })

  test('even apparently complete responses cannot prove absence without genesis coverage', async () => {
    const result = await evaluateOnchainAge(
      makeInput(),
      makeProvider(makeScan([], { fromBlock: 200n, complete: true })),
    )
    expect(result.status).toBe('unverifiable')
  })

  test('coverage ending before the snapshot cannot prove absence', async () => {
    const result = await evaluateOnchainAge(
      makeInput(),
      makeProvider(makeScan([], { toBlock: 400n })),
    )
    expect(result.status).toBe('unverifiable')
  })

  test('snapshot reorg mismatch causes unverifiable result', async () => {
    const mismatched = { ...SNAPSHOT, blockHash: OTHER_HASH }
    const result = await evaluateOnchainAge(
      makeInput(), makeProvider(makeScan([oldOutgoing], { snapshot: mismatched })),
    )
    expect(result).toMatchObject({ status: 'unverifiable', reason: 'snapshot_mismatch' })
  })

  test('provider metadata mismatch fails closed', async () => {
    const invalid = { ...makeScan([oldOutgoing]), providerId: 'unknown-provider' }
    const result = await evaluateOnchainAge(makeInput(), makeProvider(invalid))
    expect(result).toMatchObject({ status: 'unverifiable', reason: 'invalid_provider_data' })
  })

  test('provider reporting a different holder fails closed', async () => {
    const result = await evaluateOnchainAge(
      makeInput(), makeProvider(makeScan([oldOutgoing], { subjectAddress: OTHER })),
    )
    expect(result.status).toBe('unverifiable')
  })

  test('activity outside coverage fails closed', async () => {
    const result = await evaluateOnchainAge(
      makeInput(), makeProvider(makeScan([oldOutgoing], { fromBlock: 150n })),
    )
    expect(result.status).toBe('unverifiable')
  })

  test('activity with time after snapshot fails closed', async () => {
    const result = await evaluateOnchainAge(
      makeInput(),
      makeProvider(makeScan([{ ...oldOutgoing, timestamp: SNAPSHOT.timestamp + 1 }])),
    )
    expect(result.status).toBe('unverifiable')
  })

  test('unknown evidence kind fails closed rather than qualifying', () => {
    const malformed = { ...oldOutgoing, kind: 'unrecognized_provider_type' }
    const result = evaluateOnchainAgeScan(
      makeInput(), makeProvider(makeScan([])),
      makeScan([malformed as unknown as NormalizedActivity]),
    )
    expect(result).toMatchObject({ status: 'unverifiable', reason: 'invalid_provider_data' })
  })

  test('provider errors become unverifiable', async () => {
    const provider: ChainHistoryProvider = {
      id: 'fixture-provider',
      adapterVersion: 'fixture/1',
      readActivity: vi.fn(async () => { throw new Error('rate-limited') }),
    }
    const result = await evaluateOnchainAge(makeInput(), provider)
    expect(result).toMatchObject({ status: 'unverifiable', reason: 'provider_unavailable' })
  })

  test('unfinalized snapshot fails closed without calling provider', async () => {
    const provider = makeProvider(makeScan([oldOutgoing]))
    const result = await evaluateOnchainAge(
      makeInput({ ...SNAPSHOT, finality: 'safe' }),
      provider,
    )
    expect(result).toMatchObject({
      status: 'unverifiable',
      reason: 'snapshot_not_finalized',
    })
    expect(provider.readActivity).not.toHaveBeenCalled()
  })

  test('does not expose individual wallet or earliest transaction in result', async () => {
    const result = await evaluateOnchainAge(makeInput(), makeProvider(makeScan([oldOutgoing])))
    const serialized = JSON.stringify(result, (_key, value: unknown) =>
      typeof value === 'bigint' ? value.toString() : value,
    )
    expect(serialized).not.toContain(SUBJECT)
    expect(serialized).not.toContain(OTHER_HASH)
    expect(serialized).not.toContain('1_400_000_000')
  })

  test('rejects threshold dates after the snapshot', async () => {
    await expect(evaluateOnchainAge(
      { ...makeInput(), thresholdTimestamp: SNAPSHOT.timestamp + 1 },
      makeProvider(makeScan([])),
    )).rejects.toThrow('Invalid OnchainAge evaluation parameters')
  })
})
