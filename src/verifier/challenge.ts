import { base64url } from 'jose'
import type {
  OnchainAgeVerifierPolicy,
  PresentationChallengeStore,
  PresentationRequest,
} from './types.js'

export const DEFAULT_PRESENTATION_CHALLENGE_TTL_MS = 5 * 60_000
export const MAX_PRESENTATION_CHALLENGE_TTL_MS = 10 * 60_000

/**
 * Dev-only. Production needs atomic persistent single-use consumption across
 * all application instances, TTL cleanup, and issuance/verify rate limits.
 */
export class InMemoryPresentationChallengeStore implements PresentationChallengeStore {
  readonly #pending = new Map<string, PresentationRequest>()

  async save(request: PresentationRequest): Promise<void> {
    if (this.#pending.has(request.nonce)) throw new Error('Nonce collision')
    this.#pending.set(request.nonce, request)
  }

  async take(nonce: string, audience: string): Promise<PresentationRequest | undefined> {
    const request = this.#pending.get(nonce)
    if (!request || request.audience !== audience) return undefined
    this.#pending.delete(nonce)
    return request
  }
}

function assertTimestamp(value: Date): void {
  if (!Number.isFinite(value.getTime())) throw new Error('Invalid verifier clock')
}

export function parseExactIsoTime(value: string): number | undefined {
  if (typeof value !== 'string') return undefined
  const time = new Date(value)
  if (Number.isNaN(time.getTime()) || time.toISOString() !== value) return undefined
  return time.getTime()
}

function checkPolicy(policy: OnchainAgeVerifierPolicy): void {
  if (!Number.isSafeInteger(policy.chainId) || policy.chainId <= 0) throw new Error('Invalid verifier chain')
  if (!policy.issuer.startsWith('https://') || !policy.issuerKeyId.startsWith('https://')) {
    throw new Error('Verifier must pin an HTTPS issuer and key ID')
  }
  if (!policy.methodologyVersion.trim() || parseExactIsoTime(policy.requiredThresholdDate) === undefined) {
    throw new Error('Invalid OnchainAge verifier policy')
  }
}

export async function issuePresentationRequest(input: {
  /** Server-configured verifier client ID or canonical URL. */
  audience: string
  policy: OnchainAgeVerifierPolicy
  store: PresentationChallengeStore
  now?: Date
  ttlMs?: number
}): Promise<PresentationRequest> {
  checkPolicy(input.policy)
  if (!input.audience.trim()) throw new Error('Verifier audience required')
  const now = input.now ?? new Date()
  assertTimestamp(now)
  const ttlMs = input.ttlMs ?? DEFAULT_PRESENTATION_CHALLENGE_TTL_MS
  if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0 || ttlMs > MAX_PRESENTATION_CHALLENGE_TTL_MS) {
    throw new Error('Invalid presentation challenge TTL')
  }
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes) // 256 bits; unique per verifier transaction
  const nonce = base64url.encode(bytes)
  const request: PresentationRequest = {
    audience: input.audience,
    nonce,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
    policy: {
      primitive: 'OnchainAge',
      chainId: input.policy.chainId,
      methodologyVersion: input.policy.methodologyVersion,
      requiredThresholdDate: input.policy.requiredThresholdDate,
    },
  }
  await input.store.save(request)
  return request
}
