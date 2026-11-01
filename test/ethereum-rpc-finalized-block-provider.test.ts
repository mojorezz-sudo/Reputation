import { describe, expect, test, vi } from 'vitest'

import {
  EthereumRpcFinalizedBlockProvider,
  type EthereumJsonRpcClient,
} from '../src/chain-history/index.js'

function clientReturning(result: unknown): EthereumJsonRpcClient {
  return {
    async request() {
      return result
    },
  }
}

describe('EthereumRpcFinalizedBlockProvider', () => {
  test('requests the finalized block tag and returns its block number', async () => {
    const request = vi.fn(async () => ({ number: '0x1406f40' }))
    const provider = new EthereumRpcFinalizedBlockProvider(() => ({ request }))

    const blockNumber = await provider.getFinalizedBlockNumber({ chainId: 1 })

    expect(blockNumber).toBe(21_000_000n)
    expect(request).toHaveBeenCalledWith({
      method: 'eth_getBlockByNumber',
      params: ['finalized', false],
    })
  })

  test('resolves clients by chain instead of hard-coding an RPC vendor', async () => {
    const resolver = vi.fn((chainId: number) =>
      chainId === 1 ? clientReturning({ number: '0x1' }) : undefined,
    )
    const provider = new EthereumRpcFinalizedBlockProvider(resolver)

    await expect(provider.getFinalizedBlockNumber({ chainId: 1 })).resolves.toBe(1n)
    expect(resolver).toHaveBeenCalledWith(1)
  })

  test('fails closed when no RPC client is configured for the requested chain', async () => {
    const provider = new EthereumRpcFinalizedBlockProvider(() => undefined)

    await expect(
      provider.getFinalizedBlockNumber({ chainId: 8453 }),
    ).rejects.toThrow('No Ethereum RPC client configured')
  })

  test('fails closed when the RPC does not return a block object', async () => {
    const provider = new EthereumRpcFinalizedBlockProvider(() => clientReturning(null))

    await expect(
      provider.getFinalizedBlockNumber({ chainId: 1 }),
    ).rejects.toThrow('invalid finalized block')
  })

  test('fails closed when the finalized block number is malformed', async () => {
    const provider = new EthereumRpcFinalizedBlockProvider(() =>
      clientReturning({ number: '21000000' }),
    )

    await expect(
      provider.getFinalizedBlockNumber({ chainId: 1 }),
    ).rejects.toThrow('valid block number')
  })
})
