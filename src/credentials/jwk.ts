import { exportJWK, importJWK, type JWK } from 'jose'

export type NormalizedPublicP256Jwk = Readonly<{
  key: CryptoKey
  jwk: JWK
}>

export async function normalizePublicP256Jwk(
  jwk: JWK,
): Promise<NormalizedPublicP256Jwk> {
  if ('d' in jwk && jwk.d !== undefined) {
    throw new Error('public JWK must not contain private key material')
  }

  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
    throw new Error('public JWK must be an EC P-256 key')
  }

  const key = await importJWK(jwk, 'ES256')
  if (!(key instanceof CryptoKey)) {
    throw new Error('public JWK did not import as a Web Crypto key')
  }

  const normalized = await exportJWK(key)
  if ('d' in normalized && normalized.d !== undefined) {
    throw new Error('normalized public key unexpectedly contains private material')
  }

  return { key, jwk: normalized }
}
