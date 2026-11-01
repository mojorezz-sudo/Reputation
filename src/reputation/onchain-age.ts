import { isAddress, isAddressEqual, type Address, type Hex } from 'viem'

import type {
  HistoryCoverage,
  NormalizedOutboundTransaction,
  OutboundTransactionHistory,
} from '../chain-history/index.js'

export const ONCHAIN_AGE_METHODOLOGY_VERSION = 'onchain-age/0.1.0' as const

export type OnchainAgeEvidence = Readonly<{
  hash: Hex
  blockNumber: bigint
  transactionIndex: number
  timestamp: Date
}>

export type OnchainAgeUnverifiableReason =
  | 'incomplete_history'
  | 'coverage_chain_mismatch'
  | 'invalid_coverage'
  | 'transaction_chain_mismatch'
  | 'transaction_sender_mismatch'
  | 'transaction_outside_coverage'
  | 'invalid_transaction_block'
  | 'invalid_transaction_index'
  | 'invalid_transaction_timestamp'

export type OnchainAgeResult =
  | Readonly<{
      methodologyVersion: typeof ONCHAIN_AGE_METHODOLOGY_VERSION
      status: 'satisfied'
      thresholdDate: Date
      evidence: OnchainAgeEvidence
      coverage: HistoryCoverage
    }>
  | Readonly<{
      methodologyVersion: typeof ONCHAIN_AGE_METHODOLOGY_VERSION
      status: 'not_satisfied'
      thresholdDate: Date
      reason: 'no_qualifying_activity'
      coverage: HistoryCoverage
    }>
  | Readonly<{
      methodologyVersion: typeof ONCHAIN_AGE_METHODOLOGY_VERSION
      status: 'unverifiable'
      thresholdDate: Date
      reason: OnchainAgeUnverifiableReason
      coverage: HistoryCoverage
    }>

export type EvaluateOnchainAgeInput = Readonly<{
  holderAddress: Address
  chainId: number
  thresholdDate: Date
  history: OutboundTransactionHistory
}>

export function evaluateOnchainAge(
  input: EvaluateOnchainAgeInput,
): OnchainAgeResult {
  assertValidRequest(input)

  const thresholdDate = new Date(input.thresholdDate)
  const coverage = input.history.coverage
  const base = {
    methodologyVersion: ONCHAIN_AGE_METHODOLOGY_VERSION,
    thresholdDate,
    coverage,
  } as const

  const coverageProblem = validateCoverage(coverage, input.chainId)
  if (coverageProblem) {
    return {
      ...base,
      status: 'unverifiable',
      reason: coverageProblem,
    }
  }

  const transactionProblem = validateTransactions(
    input.history.transactions,
    input.chainId,
    input.holderAddress,
    coverage,
  )
  if (transactionProblem) {
    return {
      ...base,
      status: 'unverifiable',
      reason: transactionProblem,
    }
  }

  const qualifying = input.history.transactions
    .filter(
      (transaction) =>
        transaction.status === 'success' &&
        transaction.finalized &&
        transaction.timestamp.getTime() <= thresholdDate.getTime(),
    )
    .toSorted(compareEvidenceOrder)

  const evidence = qualifying[0]
  if (evidence) {
    return {
      ...base,
      status: 'satisfied',
      evidence: toEvidence(evidence),
    }
  }

  if (!coverage.complete || coverage.fromBlock !== 0n) {
    return {
      ...base,
      status: 'unverifiable',
      reason: 'incomplete_history',
    }
  }

  return {
    ...base,
    status: 'not_satisfied',
    reason: 'no_qualifying_activity',
  }
}

function assertValidRequest(input: EvaluateOnchainAgeInput): void {
  if (!Number.isInteger(input.chainId) || input.chainId <= 0) {
    throw new Error('chainId must be a positive integer')
  }

  if (!isAddress(input.holderAddress)) {
    throw new Error('holderAddress must be a valid EVM address')
  }

  if (Number.isNaN(input.thresholdDate.getTime())) {
    throw new Error('thresholdDate must be a valid Date')
  }
}

function validateCoverage(
  coverage: HistoryCoverage,
  expectedChainId: number,
): OnchainAgeUnverifiableReason | undefined {
  if (coverage.chainId !== expectedChainId) {
    return 'coverage_chain_mismatch'
  }

  if (
    coverage.providerId.trim().length === 0 ||
    coverage.fromBlock < 0n ||
    coverage.throughBlock < 0n ||
    coverage.fromBlock > coverage.throughBlock ||
    Number.isNaN(coverage.fetchedAt.getTime())
  ) {
    return 'invalid_coverage'
  }

  return undefined
}

function validateTransactions(
  transactions: readonly NormalizedOutboundTransaction[],
  expectedChainId: number,
  holderAddress: Address,
  coverage: HistoryCoverage,
): OnchainAgeUnverifiableReason | undefined {
  for (const transaction of transactions) {
    if (transaction.chainId !== expectedChainId) {
      return 'transaction_chain_mismatch'
    }

    if (!isAddress(transaction.from)) {
      return 'transaction_sender_mismatch'
    }

    if (!isAddressEqual(transaction.from, holderAddress)) {
      return 'transaction_sender_mismatch'
    }

    if (transaction.blockNumber < 0n) {
      return 'invalid_transaction_block'
    }

    if (
      transaction.blockNumber < coverage.fromBlock ||
      transaction.blockNumber > coverage.throughBlock
    ) {
      return 'transaction_outside_coverage'
    }

    if (
      !Number.isInteger(transaction.transactionIndex) ||
      transaction.transactionIndex < 0
    ) {
      return 'invalid_transaction_index'
    }

    if (Number.isNaN(transaction.timestamp.getTime())) {
      return 'invalid_transaction_timestamp'
    }
  }

  return undefined
}

function compareEvidenceOrder(
  left: NormalizedOutboundTransaction,
  right: NormalizedOutboundTransaction,
): number {
  const timeDifference = left.timestamp.getTime() - right.timestamp.getTime()
  if (timeDifference !== 0) return timeDifference

  if (left.blockNumber < right.blockNumber) return -1
  if (left.blockNumber > right.blockNumber) return 1

  const transactionIndexDifference =
    left.transactionIndex - right.transactionIndex
  if (transactionIndexDifference !== 0) return transactionIndexDifference

  return left.hash.localeCompare(right.hash)
}

function toEvidence(
  transaction: NormalizedOutboundTransaction,
): OnchainAgeEvidence {
  return {
    hash: transaction.hash,
    blockNumber: transaction.blockNumber,
    transactionIndex: transaction.transactionIndex,
    timestamp: new Date(transaction.timestamp),
  }
}
