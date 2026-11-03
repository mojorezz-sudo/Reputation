import { base64url, SignJWT } from 'jose'
import type { HolderPresentation, PresentationRequest } from './types.js'
import { parseExactIsoTime } from './challenge.js'

export const MAX_HOLDER_PROOF_TTL_SECONDS = 120
export const HOLDER_PROOF_TYPE = 'rep-holder-proof+jwt' as const

/** Binds the holder's signed presentation to the exact credential bytes. */
export async function credentialDigest(credentialJwt: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(credentialJwt))
  return base64url.encode(new Uint8Array(digest))
}

/**
 * Sandbox holder-binding proof. Not an OpenID4VP response, SD-JWT,
 * BBS proof or unlinkable ZK proof.
 */
export async function createHolderPresentation(input: {
  credentialJwt: string
  request: PresentationRequest
  holderPrivateKey: CryptoKey
  now?: Date
}): Promise<HolderPresentation> {
  const now = input.now ?? new Date()
  const issuedAt = parseExactIsoTime(input.request.issuedAt)
  const expiresAt = parseExactIsoTime(input.request.expiresAt)
  if (
    !Number.isFinite(now.getTime()) ||
    issuedAt === undefined ||
    expiresAt === undefined ||
    now.getTime() < issuedAt ||
    now.getTime() >= expiresAt ||
    !input.credentialJwt
  ) {
    throw new Error('Invalid or expired presentation request')
  }
  const nowSeconds = Math.floor(now.getTime() / 1000)
  const deadline = Math.min(
    nowSeconds + MAX_HOLDER_PROOF_TTL_SECONDS,
    Math.ceil(expiresAt / 1000),
  )
  const holderProofJwt = await new SignJWT({
    nonce: input.request.nonce,
    credentialDigest: await credentialDigest(input.credentialJwt),
  })
    .setProtectedHeader({ alg: 'ES256', typ: HOLDER_PROOF_TYPE })
    .setAudience(input.request.audience)
    .setIssuedAt(nowSeconds)
    .setExpirationTime(deadline)
    .sign(input.holderPrivateKey)

  return {
    credentialJwt: input.credentialJwt,
    holderProofJwt,
    nonce: input.request.nonce,
  }
}
