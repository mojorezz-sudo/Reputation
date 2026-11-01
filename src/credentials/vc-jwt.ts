import {
  exportJWK,
  importJWK,
  SignJWT,
  type JWK,
  type JWTPayload,
} from 'jose'

import type {
  CredentialSigner,
  OnchainAgeCredential,
  SecuredCredential,
} from './types.js'

export type VcJwtCredentialSignerOptions = Readonly<{
  issuer: string
  kid: string
  privateKey: CryptoKey
}>

/**
 * Secures VC Data Model 2.0 claims directly as `application/vc+jwt` using the
 * W3C VC JOSE/COSE processing model. It intentionally does not create the
 * legacy nested JWT claim named `vc`.
 */
export class VcJwtCredentialSigner
  implements CredentialSigner<OnchainAgeCredential>
{
  readonly mediaType = 'application/vc+jwt' as const

  readonly #issuer: string
  readonly #kid: string
  readonly #privateKey: CryptoKey

  constructor(options: VcJwtCredentialSignerOptions) {
    if (!isAbsoluteUrl(options.issuer)) {
      throw new Error('issuer must be an absolute URL')
    }
    if (!isAbsoluteUrl(options.kid)) {
      throw new Error('kid must be an absolute URL')
    }

    this.#issuer = options.issuer
    this.#kid = options.kid
    this.#privateKey = options.privateKey
  }

  async sign(input: {
    credential: OnchainAgeCredential
    holderPublicJwk: JWK
    issuedAt: Date
    signatureExpiresAt: Date
  }): Promise<SecuredCredential> {
    if (input.credential.issuer !== this.#issuer) {
      throw new Error('credential issuer does not match signer issuer')
    }

    assertValidDate(input.issuedAt, 'issuedAt')
    assertValidDate(input.signatureExpiresAt, 'signatureExpiresAt')
    if (input.signatureExpiresAt <= input.issuedAt) {
      throw new Error('signatureExpiresAt must be after issuedAt')
    }

    const holderPublicJwk = await normalizePublicP256Jwk(input.holderPublicJwk)
    const issuedAt = Math.floor(input.issuedAt.getTime() / 1_000)
    const expiresAt = Math.floor(input.signatureExpiresAt.getTime() / 1_000)

    const payload: JWTPayload = {
      ...input.credential,
      cnf: { jwk: holderPublicJwk },
    }

    const value = await new SignJWT(payload)
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'vc+jwt',
        cty: 'vc',
        kid: this.#kid,
      })
      .setIssuer(this.#issuer)
      .setIssuedAt(issuedAt)
      .setExpirationTime(expiresAt)
      .sign(this.#privateKey)

    return {
      mediaType: this.mediaType,
      value,
      validUntil: new Date(input.signatureExpiresAt),
    }
  }
}

async function normalizePublicP256Jwk(jwk: JWK): Promise<JWK> {
  if ('d' in jwk && jwk.d !== undefined) {
    throw new Error('holderPublicJwk must not contain private key material')
  }

  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
    throw new Error('holderPublicJwk must be an EC P-256 public key')
  }

  const key = await importJWK(jwk, 'ES256')
  if (!(key instanceof CryptoKey)) {
    throw new Error('holderPublicJwk did not import as a Web Crypto key')
  }

  const normalized = await exportJWK(key)
  if ('d' in normalized && normalized.d !== undefined) {
    throw new Error('normalized holder key unexpectedly contains private material')
  }

  return normalized
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
