import { describe, expect, test, vi } from 'vitest'
import type { Address } from 'viem'

import {
  EthereumRpcAccountTransactionCountProvider,
  type EthereumJsonRpcClient,
} from '../src/chain-history/index.js'

const HOLDER = '0x00000000000000000000000000000000000000A1' as Address

describe('EthereumRpcAccountTransactionCountProvider', () => {
  test('queries the account transaction count at the exact frozen block', async () => {
    const request = vi.fn(async () => '0x2a')
    const provider = new EthereumRpcAccountTransactionCountProvider(() => ({
      request,
    }))

    const count = await provider.getTransactionCount({
      chainId: 1,
      address: HOLDER,
      blockNumber: 21_000_000n,
    })

    expect(count).toBe(42n)
    expect(request).toHaveBeenCalledWith({
      method: 'eth_getTransactionCount',
      params: [HOLDER, '0x1406f40'],
    })
  })

  test('resolves RPC clients by chain instead of embedding a vendor', async () => {
    const client: EthereumJsonRpcClient = {
      async request() {
        return '0x1'
      },
    }
    const resolver = vi.fn((chainId: number) =>
      chainId === 1 ? client : undefined,
    )
    const provider = new EthereumRpcAccountTransactionCountProvider(resolver)

    await expect(
      provider.getTransactionCount({
        chainId: 1,
        address: HOLDER,
        blockNumber: 100n,
      }),
    ).resolves.toBe(1n)
    expect(resolver).toHaveBeenCalledWith(1)
  })

  test('fails closed when no RPC client is configured', async () => {
    const provider = new EthereumRpcAccountTransactionCountProvider(
      () => undefined,
    )

    await expect(
      provider.getTransactionCount({
        chainId: 8453,
        address: HOLDER,
        blockNumber: 100n,
      }),
    ).rejects.toThrow('No Ethereum RPC client configured')
  })

  test('fails closed on a malformed RPC transaction count', async () => {
    const provider = new EthereumRpcAccountTransactionCountProvider(() => ({
      async request() {
        return '42'
      },
    }))

    await expect(
      provider.getTransactionCount({
        chainId: 1,
        address: HOLDER,
        blockNumber: 100n,
      }),
    ).rejects.toThrow('invalid account transaction count')
  })
})
