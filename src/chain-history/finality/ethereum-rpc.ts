import type { FinalizedBlockProvider } from '../types.js'

export interface EthereumJsonRpcClient {
  request(input: {
    method: 'eth_getBlockByNumber'
    params: readonly ['finalized', false]
  }): Promise<unknown>
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
    if (!Number.isInteger(input.chainId) || input.chainId <= 0) {
      throw new Error('chainId must be a positive integer')
    }

    const client = this.#resolveClient(input.chainId)
    if (!client) {
      throw new Error(`No finalized-block RPC client configured for chain ${input.chainId}`)
    }

    const result = await client.request({
      method: 'eth_getBlockByNumber',
      params: ['finalized', false] as const,
    })

    if (!isRecord(result)) {
      throw new Error('RPC returned an invalid finalized block')
    }

    const number = result.number
    if (typeof number !== 'string' || !/^0x[0-9a-fA-F]+$/.test(number)) {
      throw new Error('RPC finalized block is missing a valid block number')
    }

    return BigInt(number)
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
