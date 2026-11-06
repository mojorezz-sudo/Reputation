export {
  DEFAULT_OWNERSHIP_CHALLENGE_TTL_MS,
  MAX_OWNERSHIP_CHALLENGE_TTL_MS,
  issueOwnershipChallenge,
  type IssueOwnershipChallengeInput,
} from './challenge.js'
export { InMemoryOwnershipChallengeStore } from './store.js'
export {
  createChainAwareMessageSignatureVerifier,
  MAX_CHALLENGE_CLOCK_SKEW_MS,
  eoaMessageSignatureVerifier,
  verifyOwnershipProof,
  type VerifyOwnershipProofInput,
} from './verify.js'
export type {
  MessageSignatureVerifier,
  OwnershipChallenge,
  OwnershipChallengeStore,
  OwnershipVerificationFailureReason,
  OwnershipVerificationResult,
} from './types.js'
