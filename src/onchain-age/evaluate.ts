import { getAddress, type Address, type Hex } from 'viem'

import type {
  ChainActivityScan,
  ChainHistoryProvider,
  ChainSnapshot,
  HistoryCoverage,
  NormalizedActivity,
} from '../chain-history/types.js'

export const ONCHAIN_AGE_METHODOLOGY = 'onchain-age/0.1' as const

export type OnchainAgeStatus = 'satisfied' | 'not_satisfied' | 'unverifiable'
export type OnchainAgeReason =
  | 'qualifying_activity_found'
  | 'no_qualifying_activity_in_complete_history'
  | 'incomplete_history'
  | 'snapshot_not_finalized'
  | 'snapshot_mismatch'
  | 'provider_unavailable'
  | 'invalid_provider_data'

/**
 * Internal evaluation result, not a verifiable credential or public proof.
 * It deliberately omits the subject wallet, transaction hashes and the exact
 * first-activity timestamp from the result.
 */
export type OnchainAgeResult = Readonly<{
  status: OnchainAgeStatus
  reason: OnchainAgeReason
  methodology: typeof ONCHAIN_AGE_METHODOLOGY
  chainId: number
  thresholdTimestamp: number
  asOfBlockNumber: bigint
  asOfBlockHash: Hex
  evaluatedAt: number
  providerId: string
  adapterVersion: string
  coverage?: HistoryCoverage
}>

export type EvaluateOnchainAgeInput = Readonly<{
  subjectAddress: Address
  chainId: number
  /** A canonical chain snapshot supplied by a trusted independent caller. */
  snapshot: ChainSnapshot
  /** UTC Unix seconds. Callers convert calendar months into an explicit date. */
  thresholdTimestamp: number
  evaluatedAt: number
}>

const HASH_32 = /^0x[0-9a-fA-F]{64}$/
const HASH_TX = /^0x[0-9a-fA-F]{64}$/

function validTime(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0
}

function validBlockHash(value: string): boolean {
  return HASH_32.test(value)
}

function sameSnapshot(actual: ChainSnapshot, expected: ChainSnapshot): boolean {
  return actual.chainId === expected.chainId &&
    actual.blockNumber === expected.blockNumber &&
    actual.blockHash.toLowerCase() === expected.blockHash.toLowerCase() &&
    actual.timestamp === expected.timestamp
}

function validScan(scan: ChainActivityScan, input: EvaluateOnchainAgeInput, provider: ChainHistoryProvider): boolean {
  if (
    scan.providerId !== provider.id ||
    scan.adapterVersion !== provider.adapterVersion ||
    scan.chainId !== input.chainId ||
    scan.subjectAddress.toLowerCase() !== input.subjectAddress.toLowerCase() ||
    !sameSnapshot(scan.snapshot, input.snapshot)
  ) return false

  const c = scan.coverage
  if (c.fromBlock < 0n || c.toBlock < c.fromBlock || c.toBlock > input.snapshot.blockNumber) return false
  if (!Array.isArray(scan.activities)) return false

  for (const activity of scan.activities) {
    if (
      activity.blockNumber < c.fromBlock ||
      activity.blockNumber > c.toBlock ||
      !validTime(activity.timestamp) ||
      activity.timestamp > input.snapshot.timestamp ||
      !validBlockHash(activity.blockHash)
    ) return false

    if (activity.kind === 'transaction') {
      if (!HASH_TX.test(activity.hash) ||
        !['success', 'failed', 'unknown'].includes(activity.executionStatus)) return false
      try { getAddress(activity.from) } catch { return false }
    } else if (activity.kind === 'token_transfer') {
      if (!HASH_TX.test(activity.transactionHash)) return false
      try { getAddress(activity.from); getAddress(activity.to) } catch { return false }
    } else {
      // Fail closed when an adapter emits unknown evidence types.
      return false
    }
  }
  return true
}

function qualifies(activity: NormalizedActivity, address: Address, threshold: number): boolean {
  return activity.kind === 'transaction' &&
    activity.executionStatus === 'success' &&
    activity.from.toLowerCase() === address.toLowerCase() &&
    activity.timestamp <= threshold
}

/**
 * Pure evaluation. A positive result is existential; a negative result
 * requires a complete scan from genesis through the declared snapshot.
 */
export function evaluateOnchainAgeScan(
  input: EvaluateOnchainAgeInput,
  provider: ChainHistoryProvider,
  scan: ChainActivityScan,
): OnchainAgeResult {
  const base = {
    methodology: ONCHAIN_AGE_METHODOLOGY,
    chainId: input.chainId,
    thresholdTimestamp: input.thresholdTimestamp,
    asOfBlockNumber: input.snapshot.blockNumber,
    asOfBlockHash: input.snapshot.blockHash,
    evaluatedAt: input.evaluatedAt,
    providerId: provider.id,
    adapterVersion: provider.adapterVersion,
  } as const

  if (input.snapshot.finality !== 'finalized') {
    return { ...base, status: 'unverifiable', reason: 'snapshot_not_finalized' }
  }
  if (!sameSnapshot(scan.snapshot, input.snapshot)) {
    return { ...base, status: 'unverifiable', reason: 'snapshot_mismatch' }
  }
  if (!validScan(scan, input, provider)) {
    return { ...base, status: 'unverifiable', reason: 'invalid_provider_data' }
  }

  const coverage = scan.coverage
  if (scan.activities.some((activity) => qualifies(activity, input.subjectAddress, input.thresholdTimestamp))) {
    return { ...base, coverage, status: 'satisfied', reason: 'qualifying_activity_found' }
  }
  if (
    coverage.complete &&
    coverage.fromBlock === 0n &&
    coverage.toBlock === input.snapshot.blockNumber
  ) {
    return { ...base, coverage, status: 'not_satisfied', reason: 'no_qualifying_activity_in_complete_history' }
  }
  return { ...base, coverage, status: 'unverifiable', reason: 'incomplete_history' }
}

export async function evaluateOnchainAge(
  input: EvaluateOnchainAgeInput,
  provider: ChainHistoryProvider,
): Promise<OnchainAgeResult> {
  if (
    !Number.isSafeInteger(input.chainId) || input.chainId <= 0 ||
    input.snapshot.chainId !== input.chainId ||
    input.snapshot.blockNumber < 0n ||
    !validBlockHash(input.snapshot.blockHash) ||
    !validTime(input.snapshot.timestamp) ||
    !validTime(input.thresholdTimestamp) ||
    input.thresholdTimestamp > input.snapshot.timestamp ||
    !validTime(input.evaluatedAt) ||
    !provider.id.trim() || !provider.adapterVersion.trim()
  ) throw new Error('Invalid OnchainAge evaluation parameters')
  getAddress(input.subjectAddress)

  const base = {
    methodology: ONCHAIN_AGE_METHODOLOGY,
    chainId: input.chainId,
    thresholdTimestamp: input.thresholdTimestamp,
    asOfBlockNumber: input.snapshot.blockNumber,
    asOfBlockHash: input.snapshot.blockHash,
    evaluatedAt: input.evaluatedAt,
    providerId: provider.id,
    adapterVersion: provider.adapterVersion,
  } as const

  if (input.snapshot.finality !== 'finalized') {
    return { ...base, status: 'unverifiable', reason: 'snapshot_not_finalized' }
  }

  let scan: ChainActivityScan
  try {
    scan = await provider.readActivity({
      subjectAddress: input.subjectAddress,
      chainId: input.chainId,
      snapshot: input.snapshot,
    })
  } catch {
    // Provider errors, truncated responses, rate limits and network failures
    // must never be converted to 'not_satisfied'.
    return { ...base, status: 'unverifiable', reason: 'provider_unavailable' }
  }

  return evaluateOnchainAgeScan(input, provider, scan)
}
