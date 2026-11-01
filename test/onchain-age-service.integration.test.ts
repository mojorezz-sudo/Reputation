import { describe, expect, test } from 'vitest'
import type { Address } from 'viem'

import { EtherscanV2HistoryProvider } from '../src/chain-history/index.js'
import { OnchainAgeService } from '../src/reputation/index.js'

const HOLDER = '0x00000000000000000000000000000000000000A1' as Address
const OTHER = '0x00000000000000000000000000000000000000b2' as Address
const THRESHOLD = new Date('2024-11-01T00:00:00.000Z')

function etherscanRow() {
  return {
    blockNumber: '18000000',
    timeStamp: '1704067200',
    hash: `0x${'11'.repeat(32)}`,
    transactionIndex: '7',
    from: HOLDER,
    to: OTHER,
    value: '0',
    input: '0x1234',
    txreceipt_status: '1',
    isError: '0',
  }
}

function serviceFor(input: {
  payload: unknown
  transactionCount: bigint
}) {
  const historyProvider = new EtherscanV2HistoryProvider({
    apiKey: 'fixture-api-key',
    finalizedBlockProvider: {
      async getFinalizedBlockNumber() {
        return 21_000_000n
      },
    },
    transactionCountProvider: {
      async getTransactionCount() {
        return input.transactionCount
      },
    },
    httpGet: async () => input.payload,
    clock: () => new Date('2026-11-01T16:00:00.000Z'),
    requestIntervalMs: 0,
  })

  return new OnchainAgeService(historyProvider)
}

describe('OnchainAgeService integration', () => {
  test('turns normalized old Etherscan evidence into a satisfied reputation result', async () => {
    const service = serviceFor({
      payload: { status: '1', message: 'OK', result: [etherscanRow()] },
      transactionCount: 1n,
    })

    const result = await service.evaluate({
      holderAddress: HOLDER,
      chainId: 1,
      thresholdDate: THRESHOLD,
    })

    expect(result.status).toBe('satisfied')
    if (result.status === 'satisfied') {
      expect(result.evidence.hash).toBe(`0x${'11'.repeat(32)}`)
      expect(result.coverage.complete).toBe(true)
    }
  })

  test('returns not_satisfied only when empty history is independently complete', async () => {
    const service = serviceFor({
      payload: {
        status: '0',
        message: 'No transactions found',
        result: [],
      },
      transactionCount: 0n,
    })

    const result = await service.evaluate({
      holderAddress: HOLDER,
      chainId: 1,
      thresholdDate: THRESHOLD,
    })

    expect(result).toMatchObject({
      status: 'not_satisfied',
      reason: 'no_qualifying_activity',
    })
  })

  test('returns unverifiable instead of a false negative when independent completeness does not match', async () => {
    const service = serviceFor({
      payload: {
        status: '0',
        message: 'No transactions found',
        result: [],
      },
      transactionCount: 1n,
    })

    const result = await service.evaluate({
      holderAddress: HOLDER,
      chainId: 1,
      thresholdDate: THRESHOLD,
    })

    expect(result).toMatchObject({
      status: 'unverifiable',
      reason: 'incomplete_history',
    })
  })

  test('propagates provider failures instead of converting availability problems into reputation claims', async () => {
    const service = serviceFor({
      payload: {
        status: '0',
        message: 'NOTOK',
        result: 'Max rate limit reached',
      },
      transactionCount: 0n,
    })

    await expect(
      service.evaluate({
        holderAddress: HOLDER,
        chainId: 1,
        thresholdDate: THRESHOLD,
      }),
    ).rejects.toThrow('Max rate limit reached')
  })
})
