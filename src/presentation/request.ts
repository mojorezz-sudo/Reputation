import {
  ONCHAIN_AGE_CREDENTIAL_SCHEMA_VERSION,
  ONCHAIN_AGE_CREDENTIAL_TYPE,
} from '../credentials/index.js'

export const DEFAULT_VERIFIER_REQUEST_TTL_MS = 5 * 60 * 1_000
export const MAX_VERIFIER_REQUEST_TTL_MS = 10 * 60 * 1_000

export type OnchainAgeVerificationPolicy = Readonly<{
  credentialType: typeof ONCHAIN_AGE_CREDENTIAL_TYPE
  chainId: number
  thresholdDate: Date
  acceptedMethodologyVersions: readonly string[]
  acceptedSchemaVersions: readonly [
    typeof ONCHAIN_AGE_CREDENTIAL_SCHEMA_VERSION,
    ...typeof ONCHAIN_AGE_CREDENTIAL_SCHEMA_VERSION[],
  ]
}>

export type VerifierRequest = Readonly<{
  nonce: string
  audience: string
  issuedAt: Date
  expiresAt: Date
  policy: OnchainAgeVerificationPolicy
}>

export interface VerifierRequestStore {
  save(request: VerifierRequest): Promise<void>
  get(nonce: string): Promise<VerifierRequest | undefined>
  consume(nonce: string, audience: string): Promise<VerifierRequest | undefined>
}

export class InMemoryVerifierRequestStore implements VerifierRequestStore {
  readonly #requests = new Map<string, VerifierRequest>()

  async save(request: VerifierRequest): Promise<void> {
    if (this.#requests.has(request.nonce)) {
      throw new Error('Verifier request nonce collision')
    }
    this.#requests.set(request.nonce, request)
  }

  async get(nonce: string): Promise<VerifierRequest | undefined> {
    return this.#requests.get(nonce)
  }

  async consume(
    nonce: string,
    audience: string,
  ): Promise<VerifierRequest | undefined> {
    const request = this.#requests.get(nonce)
    if (!request || request.audience !== audience) return undefined

    this.#requests.delete(nonce)
    return request
  }
}

export type IssueVerifierRequestInput = Readonly<{
  audience: string
  chainId: number
  thresholdDate: Date
  acceptedMethodologyVersions: readonly string[]
  acceptedSchemaVersions?: readonly [
    typeof ONCHAIN_AGE_CREDENTIAL_SCHEMA_VERSION,
    ...typeof ONCHAIN_AGE_CREDENTIAL_SCHEMA_VERSION[],
  ]
  now?: Date
  ttlMs?: number
}>

export async function issueVerifierRequest(
  input: IssueVerifierRequestInput,
  store: VerifierRequestStore,
): Promise<VerifierRequest> {
  const now = input.now ?? new Date()
  const ttlMs = input.ttlMs ?? DEFAULT_VERIFIER_REQUEST_TTL_MS

  assertValidDate(now, 'now')
  assertValidDate(input.thresholdDate, 'thresholdDate')
  assertAudience(input.audience)

  if (!Number.isInteger(input.chainId) || input.chainId <= 0) {
    throw new Error('chainId must be a positive integer')
  }
  if (input.acceptedMethodologyVersions.length === 0) {
    throw new Error('acceptedMethodologyVersions must not be empty')
  }
  if (
    input.acceptedMethodologyVersions.some(
      (version) => typeof version !== 'string' || version.trim().length === 0,
    )
  ) {
    throw new Error('acceptedMethodologyVersions contains an invalid version')
  }
  if (
    !Number.isInteger(ttlMs) ||
    ttlMs <= 0 ||
    ttlMs > MAX_VERIFIER_REQUEST_TTL_MS
  ) {
    throw new Error(
      `ttlMs must be an integer between 1 and ${MAX_VERIFIER_REQUEST_TTL_MS}`,
    )
  }

  const acceptedSchemaVersions =
    input.acceptedSchemaVersions ?? [ONCHAIN_AGE_CREDENTIAL_SCHEMA_VERSION]
  if (acceptedSchemaVersions.length === 0) {
    throw new Error('acceptedSchemaVersions must not be empty')
  }

  const request: VerifierRequest = {
    nonce: crypto.randomUUID().replaceAll('-', ''),
    audience: input.audience,
    issuedAt: new Date(now),
    expiresAt: new Date(now.getTime() + ttlMs),
    policy: {
      credentialType: ONCHAIN_AGE_CREDENTIAL_TYPE,
      chainId: input.chainId,
      thresholdDate: new Date(input.thresholdDate),
      acceptedMethodologyVersions: [...input.acceptedMethodologyVersions],
      acceptedSchemaVersions: [...acceptedSchemaVersions] as [
        typeof ONCHAIN_AGE_CREDENTIAL_SCHEMA_VERSION,
        ...typeof ONCHAIN_AGE_CREDENTIAL_SCHEMA_VERSION[],
      ],
    },
  }

  await store.save(request)
  return request
}

function assertAudience(value: string): void {
  try {
    const url = new URL(value)
    if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error()
  } catch {
    throw new Error('audience must be an absolute HTTP(S) URL')
  }
}

function assertValidDate(value: Date, field: string): void {
  if (Number.isNaN(value.getTime())) {
    throw new Error(`${field} must be a valid Date`)
  }
}
