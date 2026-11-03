export {
  ONCHAIN_AGE_METHODOLOGY,
  evaluateOnchainAge,
  evaluateOnchainAgeScan,
  type EvaluateOnchainAgeInput,
  type OnchainAgeReason,
  type OnchainAgeResult,
  type OnchainAgeStatus,
} from './evaluate.js'

export type {
  ChainActivityRequest,
  ChainActivityScan,
  ChainHistoryProvider,
  ChainSnapshot,
  HistoryCoverage,
  NormalizedActivity,
  NormalizedTokenTransfer,
  NormalizedTransaction,
} from '../chain-history/types.js'
