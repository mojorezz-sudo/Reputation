import { SignJWT } from 'jose'

import {
  VC_V2_CONTEXT,
  type SecuredCredential,
} from '../credentials/index.js'
import type { VerifierRequest } from './request.js'

export type EnvelopedVerifiableCredential = Readonly<{
  '@context': typeof VC_V2_CONTEXT
  id: string
  type: 'EnvelopedVerifiableCredential'
}>

export type VerifiablePresentationModel = Readonly<{
  '@context': readonly [typeof VC_V2_CONTEXT]
  type: readonly ['VerifiablePresentation']
  verifiableCredential: readonly [EnvelopedVerifiableCredential]
}>

export type SecuredPresentation = Readonly<{
  mediaType: 'application/vp+jwt'
  value: string
  expiresAt: Date
}>

export type VpJwtPresenterOptions = Readonly<{
  holderPrivateKey: CryptoKey
  clock?: () => Date
}>

export class VpJwtPresenter {
  readonly #holderPrivateKey: CryptoKey
  readonly #clock: () => Date

  constructor(options: VpJwtPresenterOptions) {
    this.#holderPrivateKey = options.holderPrivateKey
    this.#clock = options.clock ?? (() => new Date())
  }

  async present(input: {
    credential: SecuredCredential
    request: VerifierRequest
  }): Promise<SecuredPresentation> {
    if (input.credential.mediaType !== 'application/vc+jwt') {
      throw new Error('unsupported credential media type')
    }

    const now = new Date(this.#clock())
    assertValidDate(now, 'clock')
    if (now < input.request.issuedAt || now >= input.request.expiresAt) {
      throw new Error('verifier request is not currently valid')
    }
    if (input.credential.validUntil <= now) {
      throw new Error('credential is expired')
    }

    const model: VerifiablePresentationModel = {
      '@context': [VC_V2_CONTEXT],
      type: ['VerifiablePresentation'],
      verifiableCredential: [
        {
          '@context': VC_V2_CONTEXT,
          id: `data:application/vc+jwt,${input.credential.value}`,
          type: 'EnvelopedVerifiableCredential',
        },
      ],
    }

    const issuedAt = Math.floor(now.getTime() / 1_000)
    const expiresAt = Math.floor(input.request.expiresAt.getTime() / 1_000)

    const value = await new SignJWT(model)
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'vp+jwt',
        cty: 'vp',
      })
      .setAudience(input.request.audience)
      .setJti(input.request.nonce)
      .setIssuedAt(issuedAt)
      .setExpirationTime(expiresAt)
      .sign(this.#holderPrivateKey)

    return {
      mediaType: 'application/vp+jwt',
      value,
      expiresAt: new Date(input.request.expiresAt),
    }
  }
}

function assertValidDate(value: Date, field: string): void {
  if (Number.isNaN(value.getTime())) {
    throw new Error(`${field} must be a valid Date`)
  }
}
