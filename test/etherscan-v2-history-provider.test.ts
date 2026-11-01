import { describe, expect, test, vi } from 'vitest'
import type { Address } from 'viem'

import {
  EtherscanHistoryProviderError,
  EtherscanV2HistoryProvider,
  type AccountTransactionCountProvider,
  type FinalizedBlockProvider,
  type JsonHttpGet,
} from '../src/chain-history/index.js'

const HOLDER = '0x00000000000000000000000000000000000000A1' as Address
const OTHER = '0x00000000000000000000000000000000000000b2' as Address
const API_KEY = 'super-secret-test-key'

function finalizedAt(blockNumber = 21_000_000n): FinalizedBlockProvider {
  return {
    async getFinalizedBlockNumber() {
      return blockNumber
    },
  }
}

function transactionCountAt(count: bigint): AccountTransactionCountProvider {
  return {
    async getTransactionCount() {
      return count
    },
  }
}

function etherscanRow(overrides: Record<string, unknown> = {}) {
  return {
    blockNumber: '18000000',
    blockHash: `0x${'aa'.repeat(32)}`,
    timeStamp: '1704067200',
    hash: `0x${'11'.repeat(32)}`,
    nonce: '1',
    transactionIndex: '7',
    from: HOLDER,
    to: OTHER,
    value: '0',
    gas: '100000',
    gasPrice: '1000000000',
    input: '0x1234',
    methodId: '0x12345678',
    functionName: '',
    contractAddress: '',
    cumulativeGasUsed: '1234',
    txreceipt_status: '1',
    gasUsed: '50000',
    confirmations: '100',
    isError: '0',
    ...overrides,
  }
}

function ok(result: readonly unknown[]) {
  return { status: '1', message: 'OK', result }
}

function providerWithResponses(
  responses: readonly unknown[],
  overrides: {
    pageSize?: number
    maxPages?: number
    requestIntervalMs?: number
    sleep?: (milliseconds: number) => Promise<void>
    transactionCount?: bigint | null
  } = {},
) {
  const urls: URL[] = []
  let index = 0

  const httpGet: JsonHttpGet = async (url) => {
    urls.push(new URL(url))
    if (index >= responses.length) {
      throw new Error('Unexpected HTTP request')
    }
    const response = responses[index]
    index += 1
    return response
  }

  const transactionCount =
    overrides.transactionCount === undefined ? 1n : overrides.transactionCount

  const provider = new EtherscanV2HistoryProvider({
    apiKey: API_KEY,
    finalizedBlockProvider: finalizedAt(),
    ...(transactionCount === null
      ? {}
      : { transactionCountProvider: transactionCountAt(transactionCount) }),
    httpGet,
    clock: () => new Date('2026-11-01T16:00:00.000Z'),
    pageSize: overrides.pageSize ?? 2,
    maxPages: overrides.maxPages ?? 10,
    requestIntervalMs: overrides.requestIntervalMs ?? 0,
    ...(overrides.sleep ? { sleep: overrides.sleep } : {}),
  })

  return { provider, urls }
}

describe('EtherscanV2HistoryProvider', () => {
  test('freezes finality, normalizes an outbound zero-value call, and proves completeness with an independent count', async () => {
    const { provider, urls } = providerWithResponses([ok([etherscanRow()])])

    const history = await provider.getOutboundTransactions({
      chainId: 1,
      address: HOLDER,
    })

    expect(history.coverage).toEqual({
      providerId: 'etherscan-v2',
      chainId: 1,
      fromBlock: 0n,
      throughBlock: 21_000_000n,
      fetchedAt: new Date('2026-11-01T16:00:00.000Z'),
      complete: true,
    })
    expect(history.transactions).toHaveLength(1)
    expect(history.transactions[0]).toMatchObject({
      chainId: 1,
      from: HOLDER,
      to: OTHER,
      blockNumber: 18_000_000n,
      transactionIndex: 7,
      status: 'success',
      finalized: true,
      valueWei: 0n,
      input: '0x1234',
    })

    expect(urls).toHaveLength(1)
    expect(urls[0]?.searchParams.get('chainid')).toBe('1')
    expect(urls[0]?.searchParams.get('startblock')).toBe('0')
    expect(urls[0]?.searchParams.get('endblock')).toBe('21000000')
    expect(urls[0]?.searchParams.get('page')).toBe('1')
    expect(urls[0]?.searchParams.get('offset')).toBe('2')
    expect(urls[0]?.searchParams.get('sort')).toBe('asc')
  })

  test('exhausts pagination before declaring complete coverage', async () => {
    const first = etherscanRow({
      hash: `0x${'11'.repeat(32)}`,
      transactionIndex: '1',
    })
    const second = etherscanRow({
      hash: `0x${'22'.repeat(32)}`,
      transactionIndex: '2',
    })
    const third = etherscanRow({
      hash: `0x${'33'.repeat(32)}`,
      transactionIndex: '3',
    })

    const { provider, urls } = providerWithResponses(
      [ok([first, second]), ok([third])],
      { transactionCount: 3n },
    )

    const history = await provider.getOutboundTransactions({
      chainId: 1,
      address: HOLDER,
    })

    expect(history.transactions).toHaveLength(3)
    expect(history.coverage.complete).toBe(true)
    expect(urls.map((url) => url.searchParams.get('page'))).toEqual(['1', '2'])
    expect(new Set(urls.map((url) => url.searchParams.get('endblock')))).toEqual(
      new Set(['21000000']),
    )
  })

  test('accepts the narrow empty-but-valid Etherscan envelope when the independent count is zero', async () => {
    const { provider } = providerWithResponses(
      [{ status: '0', message: 'No transactions found', result: [] }],
      { transactionCount: 0n },
    )

    const history = await provider.getOutboundTransactions({
      chainId: 1,
      address: HOLDER,
    })

    expect(history.transactions).toEqual([])
    expect(history.coverage.complete).toBe(true)
  })

  test('never claims complete history when no independent count provider is configured', async () => {
    const { provider } = providerWithResponses([ok([etherscanRow()])], {
      transactionCount: null,
    })

    const history = await provider.getOutboundTransactions({
      chainId: 1,
      address: HOLDER,
    })

    expect(history.transactions).toHaveLength(1)
    expect(history.coverage.complete).toBe(false)
  })

  test('marks coverage incomplete when Etherscan rows do not match the independent account count', async () => {
    const { provider } = providerWithResponses([ok([etherscanRow()])], {
      transactionCount: 2n,
    })

    const history = await provider.getOutboundTransactions({
      chainId: 1,
      address: HOLDER,
    })

    expect(history.transactions).toHaveLength(1)
    expect(history.coverage.complete).toBe(false)
  })

  test('filters valid inbound rows from the outbound provider contract', async () => {
    const inbound = etherscanRow({ from: OTHER, to: HOLDER })
    const outbound = etherscanRow({
      hash: `0x${'22'.repeat(32)}`,
      from: HOLDER,
      to: OTHER,
    })
    const { provider } = providerWithResponses([ok([inbound, outbound]), ok([])])

    const history = await provider.getOutboundTransactions({
      chainId: 1,
      address: HOLDER,
    })

    expect(history.transactions).toHaveLength(1)
    expect(history.transactions[0]?.hash).toBe(`0x${'22'.repeat(32)}`)
    expect(history.coverage.complete).toBe(true)
  })

  test('normalizes contract creation to a null destination', async () => {
    const { provider } = providerWithResponses([
      ok([etherscanRow({ to: '', input: '0x60006000' })]),
    ])

    const history = await provider.getOutboundTransactions({
      chainId: 1,
      address: HOLDER,
    })

    expect(history.transactions[0]?.to).toBeNull()
  })

  test('marks a transaction failed when isError or receipt status indicates failure', async () => {
    const viaIsError = etherscanRow({
      hash: `0x${'44'.repeat(32)}`,
      isError: '1',
      txreceipt_status: '1',
    })
    const viaReceipt = etherscanRow({
      hash: `0x${'55'.repeat(32)}`,
      isError: '0',
      txreceipt_status: '0',
    })
    const { provider } = providerWithResponses(
      [ok([viaIsError, viaReceipt]), ok([])],
      { transactionCount: 2n },
    )

    const history = await provider.getOutboundTransactions({
      chainId: 1,
      address: HOLDER,
    })

    expect(history.transactions.map((transaction) => transaction.status)).toEqual([
      'failed',
      'failed',
    ])
    expect(history.coverage.complete).toBe(true)
  })

  test('fails rather than claiming complete coverage when the safety page limit is exhausted', async () => {
    const { provider } = providerWithResponses(
      [ok([etherscanRow(), etherscanRow({ hash: `0x${'22'.repeat(32)}` })])],
      { maxPages: 1, transactionCount: 2n },
    )

    await expect(
      provider.getOutboundTransactions({ chainId: 1, address: HOLDER }),
    ).rejects.toThrow('safety limit')
  })

  test('never converts a provider error into empty history and does not leak the API key', async () => {
    const { provider } = providerWithResponses([
      { status: '0', message: 'NOTOK', result: 'Max rate limit reached' },
    ])

    let caught: unknown
    try {
      await provider.getOutboundTransactions({ chainId: 1, address: HOLDER })
    } catch (error) {
      caught = error
    }

    expect(caught).toBeInstanceOf(EtherscanHistoryProviderError)
    expect(String(caught)).toContain('Max rate limit reached')
    expect(String(caught)).not.toContain(API_KEY)
  })

  test('sanitizes low-level HTTP failures so the API key is not propagated', async () => {
    const provider = new EtherscanV2HistoryProvider({
      apiKey: API_KEY,
      finalizedBlockProvider: finalizedAt(),
      transactionCountProvider: transactionCountAt(1n),
      httpGet: async (url) => {
        throw new Error(`network failed for ${url.toString()}`)
      },
      requestIntervalMs: 0,
    })

    let caught: unknown
    try {
      await provider.getOutboundTransactions({ chainId: 1, address: HOLDER })
    } catch (error) {
      caught = error
    }

    expect(String(caught)).toContain('Etherscan HTTP request failed')
    expect(String(caught)).not.toContain(API_KEY)
  })

  test('rejects rows beyond the independently captured finalized block', async () => {
    const { provider } = providerWithResponses([
      ok([etherscanRow({ blockNumber: '21000001' })]),
    ])

    await expect(
      provider.getOutboundTransactions({ chainId: 1, address: HOLDER }),
    ).rejects.toThrow('beyond the captured finalized block')
  })

  test('rejects malformed provider data instead of silently dropping it', async () => {
    const { provider } = providerWithResponses([
      ok([etherscanRow({ hash: 'not-a-hash' })]),
    ])

    await expect(
      provider.getOutboundTransactions({ chainId: 1, address: HOLDER }),
    ).rejects.toThrow('invalid transaction hash')
  })

  test('paces subsequent pages without delaying the first request', async () => {
    const sleep = vi.fn(async () => undefined)
    const { provider } = providerWithResponses(
      [
        ok([etherscanRow(), etherscanRow({ hash: `0x${'22'.repeat(32)}` })]),
        ok([]),
      ],
      { requestIntervalMs: 350, sleep, transactionCount: 2n },
    )

    await provider.getOutboundTransactions({ chainId: 1, address: HOLDER })

    expect(sleep).toHaveBeenCalledTimes(1)
    expect(sleep).toHaveBeenCalledWith(350)
  })
})
