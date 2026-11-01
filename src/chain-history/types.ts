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

/**
 * Independent finality boundary used by history adapters. A vendor that
 * supplies account history must not implicitly decide how far reputation data
 * is considered finalized.
 */
export interface FinalizedBlockProvider {
  getFinalizedBlockNumber(input: { chainId: number }): Promise<bigint>
}

/**
 * Independent completeness signal for EOA-style normal transaction history.
 * At a fixed block, an EOA account nonce/transaction count can be compared to
 * the number of observed outbound normal transactions from genesis.
 *
 * A mismatch must never be interpreted as complete history. Contract/smart
 * accounts may not satisfy this EOA invariant and should therefore remain
 * unverifiable until a wallet-class-specific completeness method exists.
 */
export interface AccountTransactionCountProvider {
  getTransactionCount(input: {
    chainId: number
    address: Address
    blockNumber: bigint
  }): Promise<bigint>
}
