import { describe, expect, test } from 'vitest'
import type { Address, Hex } from 'viem'

import type {
  HistoryCoverage,
  NormalizedOutboundTransaction,
  OutboundTransactionHistory,
} from '../src/chain-history/index.js'
import {
  ONCHAIN_AGE_METHODOLOGY_VERSION,
  evaluateOnchainAge,
} from '../src/reputation/index.js'

const HOLDER = '0x00000000000000000000000000000000000000a1' as Address
const OTHER = '0x00000000000000000000000000000000000000b2' as Address
const THRESHOLD = new Date('2024-11-01T00:00:00.000Z')

function coverage(
  overrides: Partial<HistoryCoverage> = {},
): HistoryCoverage {
  return {
    providerId: 'fixture-provider',
    chainId: 1,
    fromBlock: 0n,
    throughBlock: 21_000_000n,
    fetchedAt: new Date('2026-11-01T16:00:00.000Z'),
    complete: true,
    ...overrides,
  }
}

function transaction(
  overrides: Partial<NormalizedOutboundTransaction> = {},
): NormalizedOutboundTransaction {
  return {
    chainId: 1,
    hash: '0x01' as Hex,
    from: HOLDER,
    to: OTHER,
    blockNumber: 18_000_000n,
    transactionIndex: 0,
    timestamp: new Date('2024-01-01T00:00:00.000Z'),
    status: 'success',
    finalized: true,
    valueWei: 0n,
    input: '0x1234' as Hex,
    ...overrides,
  }
}

function history(
  transactions: readonly NormalizedOutboundTransaction[],
  coverageOverrides: Partial<HistoryCoverage> = {},
): OutboundTransactionHistory {
  return {
    coverage: coverage(coverageOverrides),
    transactions,
  }
}

function evaluate(
  transactionHistory: OutboundTransactionHistory,
  thresholdDate = THRESHOLD,
) {
  return evaluateOnchainAge({
    holderAddress: HOLDER,
    chainId: 1,
    thresholdDate,
    history: transactionHistory,
  })
}

describe('OnchainAge v0.1', () => {
  test('satisfies the claim with a finalized successful zero-value contract call before the threshold', () => {
    const result = evaluate(history([transaction()]))

    expect(result.methodologyVersion).toBe(ONCHAIN_AGE_METHODOLOGY_VERSION)
    expect(result.status).toBe('satisfied')
    if (result.status === 'satisfied') {
      expect(result.evidence.hash).toBe('0x01')
      expect(result.evidence.timestamp.toISOString()).toBe(
        '2024-01-01T00:00:00.000Z',
      )
    }
  })

  test('treats activity exactly on the threshold as qualifying', () => {
    const result = evaluate(
      history([transaction({ timestamp: new Date(THRESHOLD) })]),
    )

    expect(result.status).toBe('satisfied')
  })

  test('does not treat inbound-only history as qualifying', () => {
    // The provider-neutral contract contains outbound transactions only, so an
    // inbound-only wallet normalizes to an empty outbound history.
    const result = evaluate(history([]))

    expect(result).toMatchObject({
      status: 'not_satisfied',
      reason: 'no_qualifying_activity',
    })
  })

  test('ignores a failed old outbound transaction', () => {
    const result = evaluate(history([transaction({ status: 'failed' })]))

    expect(result).toMatchObject({
      status: 'not_satisfied',
      reason: 'no_qualifying_activity',
    })
  })

  test('ignores an unfinalized old outbound transaction', () => {
    const result = evaluate(history([transaction({ finalized: false })]))

    expect(result).toMatchObject({
      status: 'not_satisfied',
      reason: 'no_qualifying_activity',
    })
  })

  test('returns unverifiable when partial history contains no qualifying old evidence', () => {
    const recent = transaction({
      timestamp: new Date('2025-01-01T00:00:00.000Z'),
    })
    const result = evaluate(
      history([recent], { fromBlock: 10_000_000n, complete: true }),
    )

    expect(result).toMatchObject({
      status: 'unverifiable',
      reason: 'incomplete_history',
    })
  })

  test('can satisfy an existence claim even when source coverage is partial', () => {
    const result = evaluate(
      history([transaction()], { fromBlock: 10_000_000n, complete: true }),
    )

    expect(result.status).toBe('satisfied')
  })

  test('returns unverifiable when the provider marks its declared range incomplete', () => {
    const result = evaluate(history([], { complete: false }))

    expect(result).toMatchObject({
      status: 'unverifiable',
      reason: 'incomplete_history',
    })
  })

  test('selects qualifying evidence deterministically even when provider rows are unsorted', () => {
    const newest = transaction({
      hash: '0x03' as Hex,
      blockNumber: 18_500_000n,
      timestamp: new Date('2024-08-01T00:00:00.000Z'),
    })
    const oldest = transaction({
      hash: '0x02' as Hex,
      blockNumber: 17_000_000n,
      timestamp: new Date('2023-08-01T00:00:00.000Z'),
    })
    const middle = transaction({
      hash: '0x04' as Hex,
      blockNumber: 18_000_000n,
      timestamp: new Date('2024-01-01T00:00:00.000Z'),
    })

    const result = evaluate(history([newest, middle, oldest]))

    expect(result.status).toBe('satisfied')
    if (result.status === 'satisfied') {
      expect(result.evidence.hash).toBe('0x02')
    }
  })

  test('fails closed when coverage belongs to another chain', () => {
    const result = evaluate(history([], { chainId: 8453 }))

    expect(result).toMatchObject({
      status: 'unverifiable',
      reason: 'coverage_chain_mismatch',
    })
  })

  test('fails closed when a normalized row belongs to another chain', () => {
    const result = evaluate(history([transaction({ chainId: 8453 })]))

    expect(result).toMatchObject({
      status: 'unverifiable',
      reason: 'transaction_chain_mismatch',
    })
  })

  test('fails closed when a normalized row is not from the requested wallet', () => {
    const result = evaluate(history([transaction({ from: OTHER })]))

    expect(result).toMatchObject({
      status: 'unverifiable',
      reason: 'transaction_sender_mismatch',
    })
  })

  test('fails closed on an invalid coverage range', () => {
    const result = evaluate(
      history([], { fromBlock: 100n, throughBlock: 99n }),
    )

    expect(result).toMatchObject({
      status: 'unverifiable',
      reason: 'invalid_coverage',
    })
  })

  test('fails closed on an invalid transaction timestamp', () => {
    const result = evaluate(
      history([transaction({ timestamp: new Date('invalid') })]),
    )

    expect(result).toMatchObject({
      status: 'unverifiable',
      reason: 'invalid_transaction_timestamp',
    })
  })
})
