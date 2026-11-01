import { getAddress, isAddress, type Address } from 'viem'

import type {
  AccountTransactionCountProvider,
  FinalizedBlockProvider,
} from '../types.js'

export type EthereumJsonRpcRequest =
  | Readonly<{
      method: 'eth_getBlockByNumber'
      params: readonly ['finalized', false]
    }>
  | Readonly<{
      method: 'eth_getTransactionCount'
      params: readonly [Address, `0x${string}`]
    }>

export interface EthereumJsonRpcClient {
  request(input: EthereumJsonRpcRequest): Promise<unknown>
}

export type EthereumJsonRpcClientResolver = (
  chainId: number,
) => EthereumJsonRpcClient | undefined

export class EthereumRpcFinalizedBlockProvider
  implements FinalizedBlockProvider
{
  readonly #resolveClient: EthereumJsonRpcClientResolver

  constructor(resolveClient: EthereumJsonRpcClientResolver) {
    this.#resolveClient = resolveClient
  }

  async getFinalizedBlockNumber(input: { chainId: number }): Promise<bigint> {
    assertChainId(input.chainId)
    const client = requireClient(this.#resolveClient, input.chainId)

    const result = await client.request({
      method: 'eth_getBlockByNumber',
      params: ['finalized', false] as const,
    })

    if (!isRecord(result)) {
      throw new Error('RPC returned an invalid finalized block')
    }

    const number = result.number
    if (typeof number !== 'string' || !isHexQuantity(number)) {
      throw new Error('RPC finalized block is missing a valid block number')
    }

    return BigInt(number)
  }
}

export class EthereumRpcAccountTransactionCountProvider
  implements AccountTransactionCountProvider
{
  readonly #resolveClient: EthereumJsonRpcClientResolver

  constructor(resolveClient: EthereumJsonRpcClientResolver) {
    this.#resolveClient = resolveClient
  }

  async getTransactionCount(input: {
    chainId: number
    address: Address
    blockNumber: bigint
  }): Promise<bigint> {
    assertChainId(input.chainId)
    if (!isAddress(input.address)) {
      throw new Error('address must be a valid EVM address')
    }
    if (input.blockNumber < 0n) {
      throw new Error('blockNumber must be non-negative')
    }

    const client = requireClient(this.#resolveClient, input.chainId)
    const blockTag = `0x${input.blockNumber.toString(16)}` as const
    const result = await client.request({
      method: 'eth_getTransactionCount',
      params: [getAddress(input.address), blockTag] as const,
    })

    if (typeof result !== 'string' || !isHexQuantity(result)) {
      throw new Error('RPC returned an invalid account transaction count')
    }

    return BigInt(result)
  }
}

function requireClient(
  resolveClient: EthereumJsonRpcClientResolver,
  chainId: number,
): EthereumJsonRpcClient {
  const client = resolveClient(chainId)
  if (!client) {
    throw new Error(`No Ethereum RPC client configured for chain ${chainId}`)
  }
  return client
}

function assertChainId(chainId: number): void {
  if (!Number.isInteger(chainId) || chainId <= 0) {
    throw new Error('chainId must be a positive integer')
  }
}

function isHexQuantity(value: string): value is `0x${string}` {
  return /^0x[0-9a-fA-F]+$/.test(value)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
