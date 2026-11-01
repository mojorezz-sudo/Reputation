import type { Address, Hex } from 'viem'

export type NormalizedOutboundTransaction = Readonly<{
  chainId: number
  hash: Hex
  from: Address
  to: Address | null
  blockNumber: bigint
  transactionIndex: number
  timestamp: Date
  status: 'success' | 'failed'
  finalized: boolean
  valueWei: bigint
  input: Hex
}>

export type HistoryCoverage = Readonly<{
  providerId: string
  chainId: number
  fromBlock: bigint
  throughBlock: bigint
  fetchedAt: Date
  /**
   * The adapter asserts that the returned dataset is contiguous and complete
   * for the declared [fromBlock, throughBlock] range.
   */
  complete: boolean
}>

export type OutboundTransactionHistory = Readonly<{
  coverage: HistoryCoverage
  transactions: readonly NormalizedOutboundTransaction[]
}>

export type GetOutboundTransactionsInput = Readonly<{
  chainId: number
  address: Address
}>

/**
 * Vendor-neutral boundary. Reputation methodology must depend on this
 * interface or the normalized history model, never on a provider response.
 */
export interface ChainHistoryProvider {
  readonly id: string

  getOutboundTransactions(
    input: GetOutboundTransactionsInput,
  ): Promise<OutboundTransactionHistory>
}
