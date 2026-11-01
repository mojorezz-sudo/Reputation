import { describe, expect, test, vi } from 'vitest'
import {
  decodeJwt,
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  jwtVerify,
  type JWK,
} from 'jose'
import type { Address, Hex } from 'viem'

import {
  OnchainAgeCredentialIssuer,
  VcJwtCredentialSigner,
  type CredentialSigner,
  type OnchainAgeCredential,
  type OnchainAgeEvaluator,
} from '../src/credentials/index.js'
import { ONCHAIN_AGE_METHODOLOGY_VERSION } from '../src/reputation/index.js'

const HOLDER_ADDRESS =
  '0x00000000000000000000000000000000000000A1' as Address
const ISSUER = 'https://issuer.reputation.test'
const KID = 'https://issuer.reputation.test/keys/sandbox-1'
const NOW = new Date('2026-11-01T17:00:00.000Z')
const THRESHOLD = new Date('2024-11-01T00:00:00.000Z')

function ownership(verifiedAt = new Date('2026-11-01T16:59:00.000Z')) {
  return {
    ok: true as const,
    address: HOLDER_ADDRESS,
    chainId: 1,
    verifiedAt,
  }
}

function coverage(complete = true) {
  return {
    providerId: 'etherscan-v2',
    chainId: 1,
    fromBlock: 0n,
    throughBlock: 21_000_000n,
    fetchedAt: new Date('2026-11-01T16:58:00.000Z'),
    complete,
  }
}

function satisfiedEvaluation() {
  return {
    methodologyVersion: ONCHAIN_AGE_METHODOLOGY_VERSION,
    status: 'satisfied' as const,
    thresholdDate: new Date(THRESHOLD),
    evidence: {
      hash: `0x${'11'.repeat(32)}` as Hex,
      blockNumber: 18_000_000n,
      transactionIndex: 7,
      timestamp: new Date('2024-01-01T00:00:00.000Z'),
    },
    coverage: coverage(),
  }
}

function notSatisfiedEvaluation() {
  return {
    methodologyVersion: ONCHAIN_AGE_METHODOLOGY_VERSION,
    status: 'not_satisfied' as const,
    thresholdDate: new Date(THRESHOLD),
    reason: 'no_qualifying_activity' as const,
    coverage: coverage(),
  }
}

function unverifiableEvaluation() {
  return {
    methodologyVersion: ONCHAIN_AGE_METHODOLOGY_VERSION,
    status: 'unverifiable' as const,
    thresholdDate: new Date(THRESHOLD),
    reason: 'incomplete_history' as const,
    coverage: coverage(false),
  }
}

async function createRealIssuer() {
  const issuerKeys = await generateKeyPair('ES256', { extractable: true })
  const holderKeys = await generateKeyPair('ES256', { extractable: true })
  const holderPublicJwk = await exportJWK(holderKeys.publicKey)

  const evaluator: OnchainAgeEvaluator = {
    evaluate: vi.fn(async () => satisfiedEvaluation()),
  }
  const signer = new VcJwtCredentialSigner({
    issuer: ISSUER,
    kid: KID,
    privateKey: issuerKeys.privateKey,
  })
  const issuer = new OnchainAgeCredentialIssuer({
    issuer: ISSUER,
    evaluator,
    signer,
    clock: () => new Date(NOW),
  })

  return {
    issuer,
    evaluator,
    issuerPublicKey: issuerKeys.publicKey,
    holderPublicJwk,
    holderPrivateKey: holderKeys.privateKey,
  }
}

describe('OnchainAge credential issuance', () => {
  test('issues a direct VC 2.0 vc+jwt without exposing the source wallet or evidence transaction', async () => {
    const setup = await createRealIssuer()

    const result = await setup.issuer.issue({
      ownership: ownership(),
      thresholdDate: THRESHOLD,
      holderPublicJwk: setup.holderPublicJwk,
    })

    expect(result.status).toBe('issued')
    if (result.status !== 'issued') return

    expect(result.credential.mediaType).toBe('application/vc+jwt')
    const protectedHeader = decodeProtectedHeader(result.credential.value)
    expect(protectedHeader).toMatchObject({
      alg: 'ES256',
      typ: 'vc+jwt',
      kid: KID,
    })

    const verified = await jwtVerify(
      result.credential.value,
      setup.issuerPublicKey,
      { issuer: ISSUER },
    )
    expect(verified.protectedHeader.typ).toBe('vc+jwt')

    const payload = verified.payload
    expect(payload.iss).toBe(ISSUER)
    expect(payload.issuer).toBe(ISSUER)
    expect(payload.vc).toBeUndefined()
    expect(payload['@context']).toEqual([
      'https://www.w3.org/ns/credentials/v2',
      expect.any(Object),
    ])
    expect(payload.type).toEqual([
      'VerifiableCredential',
      'urn:reputation:type:OnchainAgeCredential',
    ])

    expect(payload.credentialSubject).toMatchObject({
      primitive: 'OnchainAge',
      chainId: 1,
      thresholdDate: THRESHOLD.toISOString(),
      methodologyVersion: ONCHAIN_AGE_METHODOLOGY_VERSION,
      schemaVersion: 'onchain-age-credential/0.1.0',
      sourceCoverage: {
        providerId: 'etherscan-v2',
        fromBlock: '0',
        throughBlock: '21000000',
        complete: true,
      },
    })

    const serializedPayload = JSON.stringify(payload)
    expect(serializedPayload).not.toContain(HOLDER_ADDRESS)
    expect(serializedPayload).not.toContain(`0x${'11'.repeat(32)}`)

    const cnf = payload.cnf as { jwk?: JWK } | undefined
    expect(cnf?.jwk).toMatchObject({ kty: 'EC', crv: 'P-256' })
    expect(cnf?.jwk?.d).toBeUndefined()

    expect(result.model.credentialSubject).not.toHaveProperty('id')
    expect(result.model.validUntil).toBe('2026-11-08T17:00:00.000Z')
  })

  test('evaluates exactly the address and chain from the fresh ownership record', async () => {
    const setup = await createRealIssuer()

    await setup.issuer.issue({
      ownership: ownership(),
      thresholdDate: THRESHOLD,
      holderPublicJwk: setup.holderPublicJwk,
    })

    expect(setup.evaluator.evaluate).toHaveBeenCalledWith({
      holderAddress: HOLDER_ADDRESS,
      chainId: 1,
      thresholdDate: THRESHOLD,
    })
  })

  test('rejects stale wallet-control verification before evaluating reputation', async () => {
    const setup = await createRealIssuer()

    await expect(
      setup.issuer.issue({
        ownership: ownership(new Date('2026-11-01T16:40:00.000Z')),
        thresholdDate: THRESHOLD,
        holderPublicJwk: setup.holderPublicJwk,
      }),
    ).rejects.toThrow('not fresh enough')

    expect(setup.evaluator.evaluate).not.toHaveBeenCalled()
  })

  test('does not issue a portable credential when reputation is not satisfied', async () => {
    const signer: CredentialSigner<OnchainAgeCredential> = {
      mediaType: 'application/vc+jwt',
      sign: vi.fn(async () => {
        throw new Error('signer should not be called')
      }),
    }
    const evaluator: OnchainAgeEvaluator = {
      evaluate: async () => notSatisfiedEvaluation(),
    }
    const issuer = new OnchainAgeCredentialIssuer({
      issuer: ISSUER,
      evaluator,
      signer,
      clock: () => new Date(NOW),
    })

    const result = await issuer.issue({
      ownership: ownership(),
      thresholdDate: THRESHOLD,
      holderPublicJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
    })

    expect(result.status).toBe('not_issued')
    if (result.status === 'not_issued') {
      expect(result.reason).toBe('reputation_not_satisfied')
    }
    expect(signer.sign).not.toHaveBeenCalled()
  })

  test('does not issue a portable credential when reputation is unverifiable', async () => {
    const signer: CredentialSigner<OnchainAgeCredential> = {
      mediaType: 'application/vc+jwt',
      sign: vi.fn(async () => {
        throw new Error('signer should not be called')
      }),
    }
    const evaluator: OnchainAgeEvaluator = {
      evaluate: async () => unverifiableEvaluation(),
    }
    const issuer = new OnchainAgeCredentialIssuer({
      issuer: ISSUER,
      evaluator,
      signer,
      clock: () => new Date(NOW),
    })

    const result = await issuer.issue({
      ownership: ownership(),
      thresholdDate: THRESHOLD,
      holderPublicJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
    })

    expect(result.status).toBe('not_issued')
    if (result.status === 'not_issued') {
      expect(result.reason).toBe('reputation_unverifiable')
    }
    expect(signer.sign).not.toHaveBeenCalled()
  })

  test('refuses holder JWKs containing private key material', async () => {
    const setup = await createRealIssuer()
    const holderPrivateJwk = await exportJWK(setup.holderPrivateKey)

    await expect(
      setup.issuer.issue({
        ownership: ownership(),
        thresholdDate: THRESHOLD,
        holderPublicJwk: holderPrivateJwk,
      }),
    ).rejects.toThrow('must not contain private key material')
  })

  test('refuses credential validity longer than the configured security maximum', async () => {
    const setup = await createRealIssuer()

    await expect(
      setup.issuer.issue({
        ownership: ownership(),
        thresholdDate: THRESHOLD,
        holderPublicJwk: setup.holderPublicJwk,
        validityMs: 30 * 24 * 60 * 60 * 1_000 + 1,
      }),
    ).rejects.toThrow('validityMs must be an integer')
  })

  test('credential payload is inspectable without relying on verifier-side custom nesting', async () => {
    const setup = await createRealIssuer()
    const result = await setup.issuer.issue({
      ownership: ownership(),
      thresholdDate: THRESHOLD,
      holderPublicJwk: setup.holderPublicJwk,
    })

    expect(result.status).toBe('issued')
    if (result.status !== 'issued') return

    const payload = decodeJwt(result.credential.value)
    expect(payload.credentialSubject).toBeDefined()
    expect(payload.vc).toBeUndefined()
  })
})
