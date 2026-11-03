export {
  DEFAULT_PRESENTATION_CHALLENGE_TTL_MS,
  InMemoryPresentationChallengeStore,
  MAX_PRESENTATION_CHALLENGE_TTL_MS,
  issuePresentationRequest,
} from './challenge.js'
export {
  createHolderPresentation,
  credentialDigest,
  HOLDER_PROOF_TYPE,
  MAX_HOLDER_PROOF_TTL_SECONDS,
} from './presentation.js'
export {
  OnchainAgeVerifier,
  type OnchainAgeVerifierOptions,
} from './verify.js'
export type {
  CredentialStatus,
  CredentialStatusChecker,
  HolderPresentation,
  OnchainAgeVerifierPolicy,
  PresentationChallengeStore,
  PresentationRequest,
  VerificationResult,
  VerifierFailureReason,
} from './types.js'
