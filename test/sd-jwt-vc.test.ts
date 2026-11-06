import { describe, expect, test, vi } from 'vitest'
import {
  base64url,
  decodeJwt,
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
} from 'jose'
import {
  ONCHAIN_AGE_CREDENTIAL_SCHEMA_VERSION,
  ONCHAIN_AGE_CREDENTIAL_TYPE,
  REPUTATION_VC_CONTEXT,
  VC_V2_CONTEXT,
  VcJwtCredentialSigner,
  type OnchainAgeCredential,
} from '../src/credentials/index.js'
import {
  issueOnchainAgeSdJwtVc,
  presentOnchainAgeSdJwtVc,
  SD_JWT_VC_DRAFT_VERSION,
  SD_JWT_VC_TYPE,
  verifyOnchainAgeSdJwtVc,
  type SdJwtOnchainAgePolicy,
} from '../src/credentials/sd-jwt-vc.js'
import { InMemoryIssuedCredentialRegistry } from '../src/issuance/index.js'
import { InMemoryDerivedCredentialStatusRegistry } from '../src/credentials/derived-status.js'

const NOW = new Date('2026-11-06T20:00:00.000Z')
const ISSUER = 'https://issuer.reputation.test'
const KID = 'https://issuer.reputation.test/keys/1'
const AUDIENCE = 'verifier_attestation:verifier.example'
const NONCE = 'n'.repeat(43)
const THRESHOLD = '2024-11-01T00:00:00.000Z'
const ORIGINAL_ID = 'urn:uuid:00000000-0000-4000-8000-000000000001'

async function setup() {
  const issuerKeys = await generateKeyPair('ES256', { extractable: true })
  const holderKeys = await generateKeyPair('ES256', { extractable: true })
  const sourceRegistry = new InMemoryIssuedCredentialRegistry()
  const newRegistry = new InMemoryDerivedCredentialStatusRegistry(sourceRegistry)
  const model: OnchainAgeCredential = {
    '@context': [VC_V2_CONTEXT, REPUTATION_VC_CONTEXT],
    type: ['VerifiableCredential', ONCHAIN_AGE_CREDENTIAL_TYPE],
    issuer: ISSUER,
    id: ORIGINAL_ID,
    validFrom: '2026-11-06T19:00:00.000Z',
    validUntil: '2026-11-09T20:00:00.000Z',
    credentialSubject: {
      primitive: 'OnchainAge',
      chainId: 1,
      thresholdDate: THRESHOLD,
      methodologyVersion: 'onchain-age/0.1.0',
      schemaVersion: ONCHAIN_AGE_CREDENTIAL_SCHEMA_VERSION,
      sourceCoverage: {
        providerId: 'fixture-private-indexer',
        fromBlock: '0',
        throughBlock: '23000000',
        complete: true,
      },
    },
  }
  const signer = new VcJwtCredentialSigner({
    issuer: ISSUER,
    kid: KID,
    privateKey: issuerKeys.privateKey,
  })
  const native = await signer.sign({
    credential: model,
    holderPublicJwk: await exportJWK(holderKeys.publicKey),
    issuedAt: new Date('2026-11-06T19:00:00.000Z'),
    signatureExpiresAt: new Date('2026-11-09T20:00:00.000Z'),
  })
  await sourceRegistry.recordIssued({
    credentialJwt: native.value,
    credentialId: ORIGINAL_ID,
    issuer: ISSUER,
    issuerKeyId: KID,
  })
  const credential = await issueOnchainAgeSdJwtVc({
    sourceVc2Jwt: native.value,
    issuer: ISSUER,
    issuerKid: KID,
    issuerPublicKey: issuerKeys.publicKey,
    issuerPrivateKey: issuerKeys.privateKey,
    sourceStatusChecker: sourceRegistry,
    newStatusRegistry: newRegistry,
    now: NOW,
  })
  const policy: SdJwtOnchainAgePolicy = {
    issuer: ISSUER,
    issuerKid: KID,
    issuerPublicKey: issuerKeys.publicKey,
    audience: AUDIENCE,
    nonce: NONCE,
    chainId: 1,
    methodologyVersion: 'onchain-age/0.1.0',
    requiredThresholdDate: THRESHOLD,
    statusChecker: newRegistry,
    now: NOW,
  }
  const presentation = await presentOnchainAgeSdJwtVc({
    credential,
    holderPrivateKey: holderKeys.privateKey,
    audience: AUDIENCE,
    nonce: NONCE,
    now: NOW,
  })
  return {
    issuerKeys, holderKeys, sourceRegistry, newRegistry, credential,
    native, model, presentation, policy,
  }
}

describe('RFC9901 SD-JWT VC draft-25 proof of concept', () => {
  test('issuer and holder cryptography verifies selected age claim with key binding', async () => {
    const x = await setup()
    expect(SD_JWT_VC_DRAFT_VERSION).toBe('draft-ietf-oauth-sd-jwt-vc-25')
    expect(x.credential.mediaType).toBe('application/dc+sd-jwt')
    const header = decodeProtectedHeader(x.credential.issuerSignedJwt)
    expect(header).toMatchObject({ alg: 'ES256', typ: 'dc+sd-jwt', kid: KID })
    const issuerClaims = decodeJwt(x.credential.issuerSignedJwt)
    expect(issuerClaims.vct).toBe(SD_JWT_VC_TYPE)
    expect(issuerClaims._sd_alg).toBe('sha-256')
    expect(issuerClaims._sd).toHaveLength(2)
    expect(issuerClaims.jti).toBeUndefined()
    expect(issuerClaims.thresholdDate).toBeUndefined()
    expect(issuerClaims).not.toHaveProperty('sourceCoverage')
    expect(issuerClaims).not.toHaveProperty('wallet')
    expect(x.presentation.split('~')).toHaveLength(3)
    expect(await verifyOnchainAgeSdJwtVc(x.presentation, x.policy)).toMatchObject({
      status: 'satisfied', chainId: 1, thresholdDate: THRESHOLD,
    })
  })

  test('minimal presentation hides provider ID and original wallet metadata', async () => {
    const x = await setup()
    expect(x.presentation).not.toContain('fixture-private-indexer')
    expect(x.presentation).not.toContain(ORIGINAL_ID)
    const disclosed = JSON.parse(new TextDecoder().decode(
      base64url.decode(x.presentation.split('~')[1]!),
    )) as unknown[]
    expect(disclosed[1]).toBe('thresholdDate')
    expect(disclosed[2]).toBe(THRESHOLD)
    expect(disclosed).toHaveLength(3)
  })

  test('holder explicitly can disclose provider but should not by default', async () => {
    const x = await setup()
    const more = await presentOnchainAgeSdJwtVc({
      credential: x.credential,
      discloseProvider: true,
      holderPrivateKey: x.holderKeys.privateKey,
      audience: AUDIENCE,
      nonce: NONCE,
      now: NOW,
    })
    expect(more.split('~')).toHaveLength(4)
    expect((await verifyOnchainAgeSdJwtVc(more, x.policy)).status).toBe('satisfied')
  })

  test('forged disclosure digest fails even with a correctly re-signed holder KB proof', async () => {
    const x = await setup()
    const fabricated = base64url.encode(JSON.stringify(['salt', 'thresholdDate', '2020-01-01T00:00:00.000Z']))
    const mutated = {
      ...x.credential,
      disclosures: { ...x.credential.disclosures, thresholdDate: fabricated },
    }
    const presentation = await presentOnchainAgeSdJwtVc({
      credential: mutated, holderPrivateKey: x.holderKeys.privateKey,
      audience: AUDIENCE, nonce: NONCE, now: NOW,
    })
    expect(await verifyOnchainAgeSdJwtVc(presentation, x.policy)).toMatchObject({
      status: 'unverifiable', reason: 'uncommitted_disclosure',
    })
  })

  test('tampering issuer JWT signature is rejected', async () => {
    const x = await setup()
    const parts = x.credential.issuerSignedJwt.split('.')
    parts[1] = base64url.encode(JSON.stringify({
      ...decodeJwt(x.credential.issuerSignedJwt), chainId: 8453,
    }))
    const malicious = await presentOnchainAgeSdJwtVc({
      credential: { ...x.credential, issuerSignedJwt: parts.join('.') },
      holderPrivateKey: x.holderKeys.privateKey,
      audience: AUDIENCE, nonce: NONCE, now: NOW,
    })
    expect((await verifyOnchainAgeSdJwtVc(malicious, x.policy)).status).toBe('unverifiable')
  })

  test('wrong holder cannot produce a valid key binding JWT', async () => {
    const x = await setup()
    const attacker = await generateKeyPair('ES256', { extractable: true })
    const proof = await presentOnchainAgeSdJwtVc({
      credential: x.credential,
      holderPrivateKey: attacker.privateKey,
      nonce: NONCE, audience: AUDIENCE, now: NOW,
    })
    expect(await verifyOnchainAgeSdJwtVc(proof, x.policy)).toMatchObject({
      status: 'unverifiable', reason: 'invalid_key_binding',
    })
  })

  test('wrong audience is rejected with a valid holder signature', async () => {
    const x = await setup()
    const proof = await presentOnchainAgeSdJwtVc({
      credential: x.credential,
      holderPrivateKey: x.holderKeys.privateKey,
      nonce: NONCE,
      audience: 'verifier_attestation:attacker.example',
      now: NOW,
    })
    expect((await verifyOnchainAgeSdJwtVc(proof, x.policy)).status).toBe('unverifiable')
  })

  test('wrong nonce is rejected with a valid holder signature', async () => {
    const x = await setup()
    const proof = await presentOnchainAgeSdJwtVc({
      credential: x.credential,
      holderPrivateKey: x.holderKeys.privateKey,
      nonce: 'z'.repeat(43), audience: AUDIENCE, now: NOW,
    })
    expect((await verifyOnchainAgeSdJwtVc(proof, x.policy)).status).toBe('unverifiable')
  })

  test('key binding digest commits to exact selected disclosures', async () => {
    const x = await setup()
    const extra = await presentOnchainAgeSdJwtVc({
      credential: x.credential, discloseProvider: true,
      holderPrivateKey: x.holderKeys.privateKey,
      nonce: NONCE, audience: AUDIENCE, now: NOW,
    })
    const parts = extra.split('~')
    // Remove the second disclosure but keep original KB JWT.
    const modified = [parts[0], parts[1], parts[3]].join('~')
    expect(await verifyOnchainAgeSdJwtVc(modified, x.policy)).toMatchObject({
      status: 'unverifiable', reason: 'invalid_key_binding',
    })
  })

  test('unsupported chain, wrong methodology or insufficient age fails policy', async () => {
    const x = await setup()
    for (const change of [
      { chainId: 8453 },
      { methodologyVersion: 'onchain-age/999' },
      { requiredThresholdDate: '2022-01-01T00:00:00.000Z' },
    ]) {
      expect(await verifyOnchainAgeSdJwtVc(x.presentation, { ...x.policy, ...change }))
        .toMatchObject({ status: 'not_satisfied', reason: 'policy_not_met' })
    }
  })

  test('source revocation stops reissuance, unknown status fails closed', async () => {
    const x = await setup()
    await x.sourceRegistry.revoke(ORIGINAL_ID)
    await expect(issueOnchainAgeSdJwtVc({
      sourceVc2Jwt: x.native.value,
      issuer: ISSUER,
      issuerKid: KID,
      issuerPublicKey: x.issuerKeys.publicKey,
      issuerPrivateKey: x.issuerKeys.privateKey,
      sourceStatusChecker: x.sourceRegistry,
      newStatusRegistry: x.newRegistry,
      now: NOW,
    })).rejects.toThrow('Source credential revoked')
  })

  test('new credential can be revoked independently from original', async () => {
    const x = await setup()
    expect((await verifyOnchainAgeSdJwtVc(x.presentation, x.policy)).status).toBe('satisfied')
    expect(await x.newRegistry.revoke(x.credential.privateCredentialId)).toBe(true)
    expect(await verifyOnchainAgeSdJwtVc(x.presentation, x.policy)).toMatchObject({
      status: 'unverifiable', reason: 'credential_revoked',
    })
    expect(await x.sourceRegistry.check({
      credentialJwt: x.native.value, issuer: ISSUER, issuerKeyId: KID,
    })).toBe('valid')
  })

  test('unknown status and checker exceptions fail closed', async () => {
    const x = await setup()
    expect(await verifyOnchainAgeSdJwtVc(x.presentation, {
      ...x.policy,
      statusChecker: { async check() { return 'unknown' } },
    })).toMatchObject({ status: 'unverifiable', reason: 'credential_status_unknown' })
    expect(await verifyOnchainAgeSdJwtVc(x.presentation, {
      ...x.policy,
      statusChecker: { async check(): Promise<'valid'> { throw Error('offline') } },
    })).toMatchObject({ status: 'unverifiable', reason: 'credential_status_unknown' })
  })

  test('different nonce and audience KB JWTs are linkable through repeated issuer signature', async () => {
    const x = await setup()
    const second = await presentOnchainAgeSdJwtVc({
      credential: x.credential,
      holderPrivateKey: x.holderKeys.privateKey,
      nonce: 'b'.repeat(43),
      audience: 'verifier_attestation:second-app.example',
      now: NOW,
    })
    const a = x.presentation.split('~')
    const b = second.split('~')
    expect(a.at(-1)).not.toBe(b.at(-1))
    expect(a[0]).toBe(b[0])
    expect(a[1]).toBe(b[1])
  })

  test('new issuance creates different credential signature + salt, but holder key still correlates', async () => {
    const x = await setup()
    const next = await issueOnchainAgeSdJwtVc({
      sourceVc2Jwt: x.native.value,
      issuer: ISSUER,
      issuerKid: KID,
      issuerPublicKey: x.issuerKeys.publicKey,
      issuerPrivateKey: x.issuerKeys.privateKey,
      sourceStatusChecker: x.sourceRegistry,
      newStatusRegistry: x.newRegistry,
      now: NOW,
    })
    expect(next.issuerSignedJwt).not.toBe(x.credential.issuerSignedJwt)
    expect(next.disclosures.thresholdDate).not.toBe(x.credential.disclosures.thresholdDate)
    expect(decodeJwt(next.issuerSignedJwt).cnf).toEqual(decodeJwt(x.credential.issuerSignedJwt).cnf)
    expect(next.privateCredentialId).not.toBe(x.credential.privateCredentialId)
  })
})
