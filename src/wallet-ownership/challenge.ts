import { getAddress, type Address } from 'viem'
import { createSiweMessage, generateSiweNonce } from 'viem/siwe'

import type {
  OwnershipChallenge,
  OwnershipChallengeStore,
} from './types.js'

export const DEFAULT_OWNERSHIP_CHALLENGE_TTL_MS = 5 * 60 * 1_000
export const MAX_OWNERSHIP_CHALLENGE_TTL_MS = 10 * 60 * 1_000

const DEFAULT_STATEMENT =
  'Prove current control of this wallet for a Reputation profile. This does not prove historical identity continuity.'

export type IssueOwnershipChallengeInput = Readonly<{
  address: Address
  chainId: number
  domain: string
  uri: string
  /** Opaque server-side holder/session reference; never expose as reputation. */
  holderSessionId: string
  /** Required server-side origin configuration; MUST NOT come from request input. */
  trustedOrigin: string
  now?: Date
  ttlMs?: number
}>

export async function issueOwnershipChallenge(
  input: IssueOwnershipChallengeInput,
  store: OwnershipChallengeStore,
): Promise<OwnershipChallenge> {
  const now = input.now ?? new Date()
  const ttlMs = input.ttlMs ?? DEFAULT_OWNERSHIP_CHALLENGE_TTL_MS

  if (Number.isNaN(now.getTime())) {
    throw new Error('Invalid challenge issue time')
  }

  if (!Number.isInteger(input.chainId) || input.chainId <= 0) {
    throw new Error('chainId must be a positive integer')
  }

  if (input.holderSessionId.trim().length === 0) {
    throw new Error('holderSessionId must not be empty')
  }

  if (
    !Number.isInteger(ttlMs) ||
    ttlMs <= 0 ||
    ttlMs > MAX_OWNERSHIP_CHALLENGE_TTL_MS
  ) {
    throw new Error(
      `ttlMs must be an integer between 1 and ${MAX_OWNERSHIP_CHALLENGE_TTL_MS}`,
    )
  }

  let configuredOrigin: URL
  let targetUri: URL
  try {
    configuredOrigin = new URL(input.trustedOrigin)
    targetUri = new URL(input.uri)
  } catch {
    throw new Error('Invalid SIWE origin or URI')
  }

  // Only server-configured origins may issue ownership challenges. Never
  // forward an untrusted request Origin/header as 'trustedOrigin'.
  const isLocal = ['localhost', '127.0.0.1', '[::1]'].includes(configuredOrigin.hostname)
  if (
    configuredOrigin.origin !== input.trustedOrigin ||
    (configuredOrigin.protocol !== 'https:' && !(isLocal && configuredOrigin.protocol === 'http:')) ||
    targetUri.origin !== configuredOrigin.origin ||
    input.domain !== configuredOrigin.host ||
    targetUri.username !== '' || targetUri.password !== '' || targetUri.hash !== ''
  ) {
    throw new Error('SIWE domain/URI must match configured trusted origin')
  }

  const address = getAddress(input.address)
  const nonce = generateSiweNonce()
  const issuedAt = new Date(now)
  const expiresAt = new Date(now.getTime() + ttlMs)

  const message = createSiweMessage({
    address,
    chainId: input.chainId,
    domain: input.domain,
    uri: input.uri,
    version: '1',
    nonce,
    issuedAt,
    expirationTime: expiresAt,
    statement: DEFAULT_STATEMENT,
  })

  const challenge: OwnershipChallenge = {
    address,
    chainId: input.chainId,
    domain: input.domain,
    uri: input.uri,
    nonce,
    message,
    issuedAt,
    expiresAt,
    holderSessionId: input.holderSessionId,
  }

  await store.save(challenge)
  return challenge
}
