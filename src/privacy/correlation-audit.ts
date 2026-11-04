import { calculateJwkThumbprint, decodeJwt, type JWK } from 'jose'

export type PresentationCorrelationAudit = Readonly<{
  exactCredentialReused: boolean
  sameSignedCredentialId: boolean
  sameHolderPublicKey: boolean
  sameIssuer: boolean
  sameClaimMetadata: boolean
  /** Only detects obvious linkability, not subtle correlation via network or attributes. */
  triviallyLinkable: boolean
}>

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : undefined
}

/**
 * Privacy regression diagnostic, NOT a security verifier.
 * JWT payload is decoded without signature validation because this test only
 * compares observable information two verifiers have received.
 * Never use these outputs to accept/reject a credential.
 */
export async function auditJwtPresentationCorrelation(
  firstJwt: string,
  secondJwt: string,
): Promise<PresentationCorrelationAudit> {
  const first = decodeJwt(firstJwt)
  const second = decodeJwt(secondJwt)
  const aCnf = record(first.cnf)
  const bCnf = record(second.cnf)
  const aJwk = record(aCnf?.jwk)
  const bJwk = record(bCnf?.jwk)

  async function thumbprint(jwk: Record<string, unknown> | undefined): Promise<string | undefined> {
    if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' ||
        typeof jwk.x !== 'string' || typeof jwk.y !== 'string') return undefined
    try {
      return await calculateJwkThumbprint(jwk as JWK, 'sha256')
    } catch {
      return undefined
    }
  }

  const [aThumb, bThumb] = await Promise.all([thumbprint(aJwk), thumbprint(bJwk)])
  const aSub = record(first.credentialSubject)
  const bSub = record(second.credentialSubject)
  const sameHolderPublicKey = aThumb !== undefined && aThumb === bThumb
  const sameSignedCredentialId =
    typeof first.jti === 'string' && first.jti.length > 0 && first.jti === second.jti

  return {
    exactCredentialReused: firstJwt === secondJwt,
    sameSignedCredentialId,
    sameHolderPublicKey,
    sameIssuer: typeof first.iss === 'string' && first.iss === second.iss,
    sameClaimMetadata: !!aSub && !!bSub && JSON.stringify(aSub) === JSON.stringify(bSub),
    triviallyLinkable: firstJwt === secondJwt || sameSignedCredentialId || sameHolderPublicKey,
  }
}
