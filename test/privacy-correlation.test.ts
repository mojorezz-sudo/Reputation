import { describe, expect, test } from 'vitest'
import { exportJWK, generateKeyPair } from 'jose'

import {
  ONCHAIN_AGE_CREDENTIAL_SCHEMA_VERSION,
  ONCHAIN_AGE_CREDENTIAL_TYPE,
  REPUTATION_VC_CONTEXT,
  VC_V2_CONTEXT,
  VcJwtCredentialSigner,
  type OnchainAgeCredential,
} from '../src/credentials/index.js'
import { auditJwtPresentationCorrelation } from '../src/privacy/index.js'
import {
  createHolderPresentation,
  InMemoryPresentationChallengeStore,
  OnchainAgeVerifier,
} from '../src/verifier/index.js'

const ISSUER = 'https://issuer.reputation.test'
const KEY_ID = 'https://issuer.reputation.test/keys/sandbox-1'
const NOW = new Date('2026-11-04T19:30:00.000Z')
const THRESHOLD = '2024-11-01T00:00:00.000Z'

function claim(id: string): OnchainAgeCredential {
  return {
    '@context': [VC_V2_CONTEXT, REPUTATION_VC_CONTEXT],
    type: ['VerifiableCredential', ONCHAIN_AGE_CREDENTIAL_TYPE],
    issuer: ISSUER,
    id,
    validFrom: '2026-11-04T18:00:00.000Z',
    validUntil: '2026-11-05T19:00:00.000Z',
    credentialSubject: {
      primitive: 'OnchainAge',
      chainId: 1,
      thresholdDate: THRESHOLD,
      methodologyVersion: 'onchain-age/0.1.0',
      schemaVersion: ONCHAIN_AGE_CREDENTIAL_SCHEMA_VERSION,
      sourceCoverage: {
        providerId: 'fixture',
        fromBlock: '0',
        throughBlock: '21000000',
        complete: true,
      },
    },
  }
}

describe('privacy correlation threat-model experiments', () => {
  test('two valid dApps can trivially link the same disclosed VC JWT', async () => {
    const issuerKeys = await generateKeyPair('ES256', { extractable: true })
    const holderKeys = await generateKeyPair('ES256', { extractable: true })
    const signer = new VcJwtCredentialSigner({
      issuer: ISSUER,
      kid: KEY_ID,
      privateKey: issuerKeys.privateKey,
    })
    const credential = await signer.sign({
      credential: claim('urn:uuid:00000000-0000-4000-8000-000000000001'),
      holderPublicJwk: await exportJWK(holderKeys.publicKey),
      issuedAt: new Date('2026-11-04T18:00:00.000Z'),
      signatureExpiresAt: new Date('2026-11-05T19:00:00.000Z'),
    })

    async function present(audience: string) {
      const verifier = new OnchainAgeVerifier({
        audience,
        policy: {
          issuer: ISSUER,
          issuerKeyId: KEY_ID,
          issuerPublicKey: issuerKeys.publicKey,
          chainId: 1,
          methodologyVersion: 'onchain-age/0.1.0',
          requiredThresholdDate: THRESHOLD,
        },
        store: new InMemoryPresentationChallengeStore(),
        statusChecker: { async check() { return 'valid' as const } },
        clock: () => new Date(NOW),
      })
      const request = await verifier.createRequest()
      const presentation = await createHolderPresentation({
        credentialJwt: credential.value,
        request,
        holderPrivateKey: holderKeys.privateKey,
        now: NOW,
      })
      expect((await verifier.verify(presentation)).status).toBe('satisfied')
      return presentation
    }

    const alpha = await present('https://app-alpha.example/verify')
    const beta = await present('https://app-beta.example/verify')
    expect(alpha.nonce).not.toBe(beta.nonce)
    expect(alpha.holderProofJwt).not.toBe(beta.holderProofJwt)

    const audit = await auditJwtPresentationCorrelation(alpha.credentialJwt, beta.credentialJwt)
    expect(audit).toMatchObject({
      exactCredentialReused: true,
      sameSignedCredentialId: true,
      sameHolderPublicKey: true,
      triviallyLinkable: true,
    })
  })

  test('different issuance keys and IDs eliminate obvious key/JTI matches, not claim metadata', async () => {
    const issuerKeys = await generateKeyPair('ES256', { extractable: true })
    const firstHolder = await generateKeyPair('ES256', { extractable: true })
    const secondHolder = await generateKeyPair('ES256', { extractable: true })
    const signer = new VcJwtCredentialSigner({
      issuer: ISSUER, kid: KEY_ID, privateKey: issuerKeys.privateKey,
    })

    async function sign(holderPublicKey: CryptoKey, id: string) {
      return (await signer.sign({
        credential: claim(id),
        holderPublicJwk: await exportJWK(holderPublicKey),
        issuedAt: new Date('2026-11-04T18:00:00.000Z'),
        signatureExpiresAt: new Date('2026-11-05T19:00:00.000Z'),
      })).value
    }

    const first = await sign(firstHolder.publicKey, 'urn:uuid:00000000-0000-4000-8000-000000000001')
    const second = await sign(secondHolder.publicKey, 'urn:uuid:00000000-0000-4000-8000-000000000002')
    const audit = await auditJwtPresentationCorrelation(first, second)
    expect(audit).toMatchObject({
      exactCredentialReused: false,
      sameSignedCredentialId: false,
      sameHolderPublicKey: false,
      sameIssuer: true,
      sameClaimMetadata: true,
      triviallyLinkable: false,
    })
    // This does NOT prove unlinkability: shared issuer, attribute values,
    // timestamps, network and browser metadata may still reveal identity.
  })
})
