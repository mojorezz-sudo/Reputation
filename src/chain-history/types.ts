import type { Address, Hex } from 'viem'

/** Normalized, provider-neutral snapshot. The caller must establish canonicality. */
export type ChainSnapshot = Readonly<{
  chainId: number
  blockNumber: bigint
  blockHash: Hex
  timestamp: number // Unix seconds
  finality: 'finalized' | 'safe' | 'unconfirmed'
}>

/** Only a successful holder-initiated L1 transaction qualifies for OnchainAge v0.1. */
export type NormalizedTransaction = Readonly<{
  kind: 'transaction'
  hash: Hex
  from: Address
  blockNumber: bigint
  blockHash: Hex
  timestamp: number
  executionStatus: 'success' | 'failed' | 'unknown'
}>

/** Included to prove that token receipts/events are never accidentally counted. */
export type NormalizedTokenTransfer = Readonly<{
  kind: 'token_transfer'
  transactionHash: Hex
  from: Address
  to: Address
  blockNumber: bigint
  blockHash: Hex
  timestamp: number
}>

export type NormalizedActivity = NormalizedTransaction | NormalizedTokenTransfer

export type HistoryCoverage = Readonly<{
  fromBlock: bigint
  toBlock: bigint
  /**
   * True only when all relevant activity in the stated block interval was
   * examined without truncation, gaps or pagination errors. Never infer this
   * from a successful HTTP response alone.
   */
  complete: boolean
}>

export type ChainActivityScan = Readonly<{
  chainId: number
  subjectAddress: Address
  providerId: string
  adapterVersion: string
  snapshot: ChainSnapshot
  coverage: HistoryCoverage
  activities: readonly NormalizedActivity[]
}>

export type ChainActivityRequest = Readonly<{
  chainId: number
  subjectAddress: Address
  snapshot: ChainSnapshot
}>

/** Swappable adapter; domain logic must never import a vendor SDK. */
export interface ChainHistoryProvider {
  readonly id: string
  readonly adapterVersion: string
  readActivity(request: ChainActivityRequest): Promise<ChainActivityScan>
}
