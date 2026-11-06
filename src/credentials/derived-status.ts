import { base64url } from 'jose'
import {
  InMemoryIssuedCredentialRegistry,
} from '../issuance/secure-session.js'
import type { CredentialStatus, CredentialStatusChecker } from '../verifier/types.js'

export interface DerivedCredentialStatusRegistry extends CredentialStatusChecker {
  /**
   * The issuer must link reissued credentials to their canonical source.
   * Without this, revoking the source does NOT invalidate old derivatives.
   */
  recordDerived(input: {
    credentialJwt: string
    issuer: string
    issuerKeyId: string
    credentialId: string
    sourceVc2Jwt: string
  }): Promise<void>
}

async function digest(value: string): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return base64url.encode(new Uint8Array(d))
}

/**
 * DEVELOPMENT ONLY! It retains source JWTs in server RAM for parent-status
 * checks; never deploy this class on an HTTP verifier. A production issuer
 * must use signed, privacy-preserving status lists with documented lineage,
 * cache freshness and independent key/status rotation.
 *
 * All check results fail closed on lost parent records or network errors.
 */
export class InMemoryDerivedCredentialStatusRegistry implements DerivedCredentialStatusRegistry {
  readonly #own = new InMemoryIssuedCredentialRegistry()
  readonly #parentStatus: CredentialStatusChecker
  readonly #parents = new Map<string, {
    sourceVc2Jwt: string
    issuer: string
    issuerKeyId: string
  }>()

  constructor(parentStatus: CredentialStatusChecker) {
    this.#parentStatus = parentStatus
  }

  async recordDerived(input: {
    credentialJwt: string
    issuer: string
    issuerKeyId: string
    credentialId: string
    sourceVc2Jwt: string
  }): Promise<void> {
    const key = await digest(input.credentialJwt)
    if (this.#parents.has(key)) throw new Error('Duplicate derived credential')
    await this.#own.recordIssued(input)
    this.#parents.set(key, {
      sourceVc2Jwt: input.sourceVc2Jwt,
      issuer: input.issuer,
      issuerKeyId: input.issuerKeyId,
    })
  }

  async revoke(credentialId: string): Promise<boolean> {
    return this.#own.revoke(credentialId)
  }

  async check(input: {
    credentialJwt: string
    issuer: string
    issuerKeyId: string
  }): Promise<CredentialStatus> {
    const ownStatus = await this.#own.check(input)
    if (ownStatus !== 'valid') return ownStatus

    const key = await digest(input.credentialJwt)
    const parent = this.#parents.get(key)
    if (!parent || parent.issuer !== input.issuer ||
        parent.issuerKeyId !== input.issuerKeyId) return 'unknown'
    try {
      const source = await this.#parentStatus.check({
        credentialJwt: parent.sourceVc2Jwt,
        issuer: parent.issuer,
        issuerKeyId: parent.issuerKeyId,
      })
      return source === 'valid' ? 'valid' :
        source === 'revoked' ? 'revoked' : 'unknown'
    } catch {
      return 'unknown'
    }
  }
}
