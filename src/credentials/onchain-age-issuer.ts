import type { JWK } from 'jose'

import type { OwnershipVerificationResult } from '../wallet-ownership/index.js'
import type {
  EvaluateWalletOnchainAgeInput,
  OnchainAgeResult,
} from '../reputation/index.js'
import {
  ONCHAIN_AGE_CREDENTIAL_SCHEMA_VERSION,
  ONCHAIN_AGE_CREDENTIAL_TYPE,
  REPUTATION_VC_CONTEXT,
  VC_V2_CONTEXT,
  type CredentialSigner,
  type OnchainAgeCredential,
  type SecuredCredential,
} from './types.js'

export const DEFAULT_ONCHAIN_AGE_CREDENTIAL_VALIDITY_MS =
  7 * 24 * 60 * 60 * 1_000
export const MAX_ONCHAIN_AGE_CREDENTIAL_VALIDITY_MS =
  30 * 24 * 60 * 60 * 1_000
export const DEFAULT_MAX_OWNERSHIP_VERIFICATION_AGE_MS = 10 * 60 * 1_000

export type SuccessfulOwnershipVerification = Extract<
  OwnershipVerificationResult,
  { ok: true }
>

export interface OnchainAgeEvaluator {
  evaluate(input: EvaluateWalletOnchainAgeInput): Promise<OnchainAgeResult>
}

export type OnchainAgeCredentialIssuanceResult =
  | Readonly<{
      status: 'issued'
      credential: SecuredCredential
      model: OnchainAgeCredential
    }>
  | Readonly<{
      status: 'not_issued'
      reason: 'reputation_not_satisfied' | 'reputation_unverifiable'
      evaluation: OnchainAgeResult
    }>

export type OnchainAgeCredentialIssuerOptions = Readonly<{
  issuer: string
  evaluator: OnchainAgeEvaluator
  signer: CredentialSigner<OnchainAgeCredential>
  clock?: () => Date
  defaultValidityMs?: number
  maxOwnershipVerificationAgeMs?: number
}>

/**
 * Application-level issuance boundary.
 *
 * It does not accept a caller-supplied reputation result. It starts from a
 * server-created successful wallet-control verification and invokes the
 * OnchainAge evaluator itself, keeping issuance tied to the verified address.
 */
export class OnchainAgeCredentialIssuer {
  readonly #issuer: string
  readonly #evaluator: OnchainAgeEvaluator
  readonly #signer: CredentialSigner<OnchainAgeCredential>
  readonly #clock: () => Date
  readonly #defaultValidityMs: number
  readonly #maxOwnershipVerificationAgeMs: number

  constructor(options: OnchainAgeCredentialIssuerOptions) {
    if (!isAbsoluteUrl(options.issuer)) {
      throw new Error('issuer must be an absolute URL')
    }

    const defaultValidityMs =
      options.defaultValidityMs ?? DEFAULT_ONCHAIN_AGE_CREDENTIAL_VALIDITY_MS
    assertValidity(defaultValidityMs)

    const maxOwnershipVerificationAgeMs =
      options.maxOwnershipVerificationAgeMs ??
      DEFAULT_MAX_OWNERSHIP_VERIFICATION_AGE_MS
    if (
      !Number.isInteger(maxOwnershipVerificationAgeMs) ||
      maxOwnershipVerificationAgeMs <= 0
    ) {
      throw new Error('maxOwnershipVerificationAgeMs must be a positive integer')
    }

    this.#issuer = options.issuer
    this.#evaluator = options.evaluator
    this.#signer = options.signer
    this.#clock = options.clock ?? (() => new Date())
    this.#defaultValidityMs = defaultValidityMs
    this.#maxOwnershipVerificationAgeMs = maxOwnershipVerificationAgeMs
  }

  async issue(input: {
    ownership: SuccessfulOwnershipVerification
    thresholdDate: Date
    holderPublicJwk: JWK
    validityMs?: number
  }): Promise<OnchainAgeCredentialIssuanceResult> {
    const now = new Date(this.#clock())
    assertValidDate(now, 'clock')
    assertValidDate(input.thresholdDate, 'thresholdDate')

    const ownershipAgeMs = now.getTime() - input.ownership.verifiedAt.getTime()
    if (
      Number.isNaN(ownershipAgeMs) ||
      ownershipAgeMs < 0 ||
      ownershipAgeMs > this.#maxOwnershipVerificationAgeMs
    ) {
      throw new Error('wallet ownership verification is not fresh enough for issuance')
    }

    const validityMs = input.validityMs ?? this.#defaultValidityMs
    assertValidity(validityMs)

    const evaluation = await this.#evaluator.evaluate({
      holderAddress: input.ownership.address,
      chainId: input.ownership.chainId,
      thresholdDate: input.thresholdDate,
    })

    if (evaluation.status === 'not_satisfied') {
      return {
        status: 'not_issued',
        reason: 'reputation_not_satisfied',
        evaluation,
      }
    }

    if (evaluation.status === 'unverifiable') {
      return {
        status: 'not_issued',
        reason: 'reputation_unverifiable',
        evaluation,
      }
    }

    const validUntil = new Date(now.getTime() + validityMs)
    const model = buildCredentialModel({
      issuer: this.#issuer,
      now,
      validUntil,
      evaluation,
    })

    const credential = await this.#signer.sign({
      credential: model,
      holderPublicJwk: input.holderPublicJwk,
      issuedAt: now,
      signatureExpiresAt: validUntil,
    })

    return {
      status: 'issued',
      credential,
      model,
    }
  }
}

function buildCredentialModel(input: {
  issuer: string
  now: Date
  validUntil: Date
  evaluation: Extract<OnchainAgeResult, { status: 'satisfied' }>
}): OnchainAgeCredential {
  return {
    '@context': [VC_V2_CONTEXT, REPUTATION_VC_CONTEXT],
    type: ['VerifiableCredential', ONCHAIN_AGE_CREDENTIAL_TYPE],
    issuer: input.issuer,
    id: `urn:uuid:${crypto.randomUUID()}`,
    validFrom: input.now.toISOString(),
    validUntil: input.validUntil.toISOString(),
    credentialSubject: {
      primitive: 'OnchainAge',
      chainId: input.evaluation.coverage.chainId,
      thresholdDate: input.evaluation.thresholdDate.toISOString(),
      methodologyVersion: input.evaluation.methodologyVersion,
      schemaVersion: ONCHAIN_AGE_CREDENTIAL_SCHEMA_VERSION,
      sourceCoverage: {
        providerId: input.evaluation.coverage.providerId,
        fromBlock: input.evaluation.coverage.fromBlock.toString(),
        throughBlock: input.evaluation.coverage.throughBlock.toString(),
        complete: input.evaluation.coverage.complete,
      },
    },
  }
}

function assertValidity(validityMs: number): void {
  if (
    !Number.isInteger(validityMs) ||
    validityMs <= 0 ||
    validityMs > MAX_ONCHAIN_AGE_CREDENTIAL_VALIDITY_MS
  ) {
    throw new Error(
      `validityMs must be an integer between 1 and ${MAX_ONCHAIN_AGE_CREDENTIAL_VALIDITY_MS}`,
    )
  }
}

function assertValidDate(value: Date, field: string): void {
  if (Number.isNaN(value.getTime())) {
    throw new Error(`${field} must be a valid Date`)
  }
}

function isAbsoluteUrl(value: string): boolean {
  try {
    const url = new URL(value)
    return url.protocol === 'https:' || url.protocol === 'http:'
  } catch {
    return false
  }
}
