import { describe, expect, test, vi } from 'vitest'
import {
  decodeJwt,
  exportJWK,
  generateKeyPair,
  SignJWT,
} from 'jose'
import type { Address, Hex } from 'viem'
import {
  OnchainAgeCredentialIssuer,
  ONCHAIN_AGE_CREDENTIAL_TYPE,
  ONCHAIN_AGE_CREDENTIAL_SCHEMA_VERSION,
  REPUTATION_VC_CONTEXT,
  VC_V2_CONTEXT,
  VcJwtCredentialSigner,
  type OnchainAgeCredential,
} from '../src/credentials/index.js'
import {
  credentialDigest,
  createHolderPresentation,
  HOLDER_PROOF_TYPE,
  InMemoryPresentationChallengeStore,
  OnchainAgeVerifier,
  type CredentialStatus,
  type OnchainAgeVerifierPolicy,
} from '../src/verifier/index.js'

const ISSUER = 'https://issuer.reputation.test'
const KID = 'https://issuer.reputation.test/keys/sandbox-1'
const AUDIENCE = 'https://app.example/verify'
const OTHER_AUDIENCE = 'https://malicious.example/verify'
const NOW = new Date('2026-11-03T18:00:00.000Z')
const THRESHOLD = '2024-11-01T00:00:00.000Z'

function claim(issuer = ISSUER, threshold = THRESHOLD, chainId = 1): OnchainAgeCredential {
  return {
    '@context': [VC_V2_CONTEXT, REPUTATION_VC_CONTEXT],
    type: ['VerifiableCredential', ONCHAIN_AGE_CREDENTIAL_TYPE],
    issuer,
    validFrom: '2026-11-03T17:00:00.000Z',
    validUntil: '2026-11-04T18:00:00.000Z',
    credentialSubject: {
      primitive: 'OnchainAge',
      chainId,
      thresholdDate: threshold,
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

async function setup(options: {
  status?: CredentialStatus
  threshold?: string
  chainId?: number
  methodology?: string
} = {}) {
  const issuerKeys = await generateKeyPair('ES256', { extractable: true })
  const holderKeys = await generateKeyPair('ES256', { extractable: true })
  const holderPublicJwk = await exportJWK(holderKeys.publicKey)
  const signer = new VcJwtCredentialSigner({
    issuer: ISSUER,
    kid: KID,
    privateKey: issuerKeys.privateKey,
  })
  const credential = await signer.sign({
    credential: claim(),
    holderPublicJwk,
    issuedAt: new Date('2026-11-03T17:00:00.000Z'),
    signatureExpiresAt: new Date('2026-11-04T18:00:00.000Z'),
  })
  const store = new InMemoryPresentationChallengeStore()
  const statusChecker = {
    check: vi.fn(async (): Promise<CredentialStatus> => options.status ?? 'valid'),
  }
  const policy: OnchainAgeVerifierPolicy = {
    issuer: ISSUER,
    issuerKeyId: KID,
    issuerPublicKey: issuerKeys.publicKey,
    chainId: options.chainId ?? 1,
    methodologyVersion: options.methodology ?? 'onchain-age/0.1.0',
    requiredThresholdDate: options.threshold ?? THRESHOLD,
  }
  const verifier = new OnchainAgeVerifier({
    audience: AUDIENCE,
    policy,
    store,
    statusChecker,
    clock: () => new Date(NOW),
  })
  const request = await verifier.createRequest()
  const presentation = await createHolderPresentation({
    credentialJwt: credential.value,
    request,
    holderPrivateKey: holderKeys.privateKey,
    now: NOW,
  })
  return {
    issuerKeys, holderKeys, holderPublicJwk, signer, credential, request,
    presentation, verifier, store, statusChecker, policy,
  }
}

async function customHolderProof(input: {
  key: CryptoKey
  nonce: string
  audience: string
  credentialJwt: string
  digest?: string
  iat?: number
  exp?: number
}) {
  const now = Math.floor(NOW.getTime() / 1000)
  return new SignJWT({
    nonce: input.nonce,
    credentialDigest: input.digest ?? await credentialDigest(input.credentialJwt),
  })
    .setProtectedHeader({ alg: 'ES256', typ: HOLDER_PROOF_TYPE })
    .setAudience(input.audience)
    .setIssuedAt(input.iat ?? now)
    .setExpirationTime(input.exp ?? now + 90)
    .sign(input.key)
}

describe('sandbox verifier: issuer + holder + nonce + audience', () => {
  test('accepts valid credential and fresh holder-bound presentation', async () => {
    const x = await setup()
    expect(x.request.nonce).toMatch(/^[A-Za-z0-9_-]{40,}$/)
    expect(await x.verifier.verify(x.presentation)).toMatchObject({
      status: 'satisfied',
      chainId: 1,
      thresholdDate: THRESHOLD,
      methodologyVersion: 'onchain-age/0.1.0',
    })
    expect(x.statusChecker.check).toHaveBeenCalledTimes(1)
  })

  test('rejects reuse of the same presentation and nonce', async () => {
    const x = await setup()
    expect((await x.verifier.verify(x.presentation)).status).toBe('satisfied')
    expect(await x.verifier.verify(x.presentation)).toEqual({
      status: 'unverifiable',
      reason: 'challenge_not_found_or_consumed',
    })
  })

  test('allows same credential with fresh nonce and newly signed holder proof', async () => {
    const x = await setup()
    expect((await x.verifier.verify(x.presentation)).status).toBe('satisfied')
    const nextRequest = await x.verifier.createRequest()
    expect(nextRequest.nonce).not.toBe(x.request.nonce)
    const next = await createHolderPresentation({
      credentialJwt: x.credential.value,
      request: nextRequest,
      holderPrivateKey: x.holderKeys.privateKey,
      now: NOW,
    })
    expect((await x.verifier.verify(next)).status).toBe('satisfied')
  })

  test('concurrent submissions of same nonce succeed at most once', async () => {
    const x = await setup()
    const results = await Promise.all([
      x.verifier.verify(x.presentation),
      x.verifier.verify(x.presentation),
      x.verifier.verify(x.presentation),
    ])
    expect(results.filter(r => r.status === 'satisfied')).toHaveLength(1)
  })

  test('rejects holder proof created for another audience', async () => {
    const x = await setup()
    const forged = await customHolderProof({
      key: x.holderKeys.privateKey, nonce: x.request.nonce,
      audience: OTHER_AUDIENCE, credentialJwt: x.credential.value,
    })
    expect(await x.verifier.verify({ ...x.presentation, holderProofJwt: forged })).toMatchObject({
      status: 'unverifiable',
      reason: 'invalid_holder_proof',
    })
  })

  test('wrong audience cannot consume correct verifier challenge', async () => {
    const x = await setup()
    const wrong = new OnchainAgeVerifier({
      audience: OTHER_AUDIENCE,
      policy: x.policy,
      store: x.store,
      statusChecker: x.statusChecker,
      clock: () => new Date(NOW),
    })
    expect(await wrong.verify(x.presentation)).toMatchObject({
      status: 'unverifiable',
      reason: 'challenge_not_found_or_consumed',
    })
    expect((await x.verifier.verify(x.presentation)).status).toBe('satisfied')
  })

  test('rejects nonce mismatch within valid holder signature', async () => {
    const x = await setup()
    const oldProof = await customHolderProof({
      key: x.holderKeys.privateKey, nonce: 'different-nonce',
      audience: AUDIENCE, credentialJwt: x.credential.value,
    })
    expect(await x.verifier.verify({ ...x.presentation, holderProofJwt: oldProof })).toMatchObject({
      status: 'unverifiable', reason: 'invalid_holder_proof',
    })
  })

  test('rejects proof signed by wrong holder key even with correct credential', async () => {
    const x = await setup()
    const alien = await generateKeyPair('ES256', { extractable: true })
    const invalid = await customHolderProof({
      key: alien.privateKey, nonce: x.request.nonce,
      audience: AUDIENCE, credentialJwt: x.credential.value,
    })
    expect(await x.verifier.verify({ ...x.presentation, holderProofJwt: invalid })).toMatchObject({
      status: 'unverifiable', reason: 'invalid_holder_proof',
    })
  })

  test('rejects substitution of another credential JWT after holder signs', async () => {
    const x = await setup()
    const swapped = await x.signer.sign({
      credential: claim(ISSUER, '2023-11-01T00:00:00.000Z'),
      holderPublicJwk: x.holderPublicJwk,
      issuedAt: new Date('2026-11-03T17:00:00.000Z'),
      signatureExpiresAt: new Date('2026-11-04T18:00:00.000Z'),
    })
    expect(await x.verifier.verify({
      ...x.presentation, credentialJwt: swapped.value,
    })).toMatchObject({ status: 'unverifiable', reason: 'invalid_holder_proof' })
  })

  test('rejects credential signed by a different issuer key', async () => {
    const x = await setup()
    const attacker = await generateKeyPair('ES256', { extractable: true })
    const forgedSigner = new VcJwtCredentialSigner({
      issuer: ISSUER, kid: KID, privateKey: attacker.privateKey,
    })
    const forged = await forgedSigner.sign({
      credential: claim(), holderPublicJwk: x.holderPublicJwk,
      issuedAt: new Date('2026-11-03T17:00:00.000Z'),
      signatureExpiresAt: new Date('2026-11-04T18:00:00.000Z'),
    })
    const proof = await customHolderProof({
      key: x.holderKeys.privateKey, nonce: x.request.nonce,
      audience: AUDIENCE, credentialJwt: forged.value,
    })
    expect(await x.verifier.verify({
      nonce: x.request.nonce, holderProofJwt: proof, credentialJwt: forged.value,
    })).toMatchObject({ status: 'unverifiable', reason: 'invalid_credential' })
  })

  test('rejects a credential from another issuer identity', async () => {
    const x = await setup()
    const otherIssuer = 'https://wrong-issuer.test'
    const malicious = new VcJwtCredentialSigner({
      issuer: otherIssuer, kid: KID, privateKey: x.issuerKeys.privateKey,
    })
    const forged = await malicious.sign({
      credential: claim(otherIssuer), holderPublicJwk: x.holderPublicJwk,
      issuedAt: new Date('2026-11-03T17:00:00.000Z'),
      signatureExpiresAt: new Date('2026-11-04T18:00:00.000Z'),
    })
    const proof = await customHolderProof({
      key: x.holderKeys.privateKey, nonce: x.request.nonce,
      audience: AUDIENCE, credentialJwt: forged.value,
    })
    expect(await x.verifier.verify({
      nonce: x.request.nonce, credentialJwt: forged.value, holderProofJwt: proof,
    })).toMatchObject({ status: 'unverifiable', reason: 'invalid_credential' })
  })

  test('rejects issuer key ID mismatch even when signature is cryptographically valid', async () => {
    const x = await setup()
    const otherKidSigner = new VcJwtCredentialSigner({
      issuer: ISSUER,
      kid: 'https://issuer.reputation.test/keys/other',
      privateKey: x.issuerKeys.privateKey,
    })
    const forged = await otherKidSigner.sign({
      credential: claim(), holderPublicJwk: x.holderPublicJwk,
      issuedAt: new Date('2026-11-03T17:00:00.000Z'),
      signatureExpiresAt: new Date('2026-11-04T18:00:00.000Z'),
    })
    const proof = await customHolderProof({
      key: x.holderKeys.privateKey, nonce: x.request.nonce,
      audience: AUDIENCE, credentialJwt: forged.value,
    })
    expect(await x.verifier.verify({
      nonce: x.request.nonce, credentialJwt: forged.value, holderProofJwt: proof,
    })).toMatchObject({ status: 'unverifiable', reason: 'invalid_credential' })
  })

  test('rejects expired issuer credential', async () => {
    const x = await setup()
    const expired = await x.signer.sign({
      credential: { ...claim(), validFrom: '2026-11-01T00:00:00.000Z', validUntil: '2026-11-02T00:00:00.000Z' },
      holderPublicJwk: x.holderPublicJwk,
      issuedAt: new Date('2026-11-01T00:00:00.000Z'),
      signatureExpiresAt: new Date('2026-11-02T00:00:00.000Z'),
    })
    const proof = await customHolderProof({
      key: x.holderKeys.privateKey, nonce: x.request.nonce,
      audience: AUDIENCE, credentialJwt: expired.value,
    })
    expect(await x.verifier.verify({
      nonce: x.request.nonce, credentialJwt: expired.value, holderProofJwt: proof,
    })).toMatchObject({ status: 'unverifiable', reason: 'invalid_credential' })
  })

  test('rejects expired holder proof', async () => {
    const x = await setup()
    const now = Math.floor(NOW.getTime() / 1000)
    const oldProof = await customHolderProof({
      key: x.holderKeys.privateKey, nonce: x.request.nonce,
      audience: AUDIENCE, credentialJwt: x.credential.value,
      iat: now - 300, exp: now - 100,
    })
    expect(await x.verifier.verify({ ...x.presentation, holderProofJwt: oldProof })).toMatchObject({
      status: 'unverifiable', reason: 'invalid_holder_proof',
    })
  })

  test('rejects holder proofs with excessively long validity', async () => {
    const x = await setup()
    const now = Math.floor(NOW.getTime() / 1000)
    const longProof = await customHolderProof({
      key: x.holderKeys.privateKey, nonce: x.request.nonce,
      audience: AUDIENCE, credentialJwt: x.credential.value,
      iat: now, exp: now + 3600,
    })
    expect(await x.verifier.verify({ ...x.presentation, holderProofJwt: longProof })).toMatchObject({
      status: 'unverifiable', reason: 'invalid_holder_proof',
    })
  })

  test('rejects no-longer-fresh challenge before evaluating signature', async () => {
    const x = await setup()
    const expiredVerifier = new OnchainAgeVerifier({
      audience: AUDIENCE, policy: x.policy, store: x.store,
      statusChecker: x.statusChecker,
      clock: () => new Date(NOW.getTime() + 6 * 60_000),
    })
    expect(await expiredVerifier.verify(x.presentation)).toMatchObject({
      status: 'unverifiable', reason: 'challenge_expired',
    })
  })

  test('returns not_satisfied when signed age claim is weaker than requested threshold', async () => {
    const x = await setup()
    const weaker = await x.signer.sign({
      credential: claim(ISSUER, '2025-11-01T00:00:00.000Z'),
      holderPublicJwk: x.holderPublicJwk,
      issuedAt: new Date('2026-11-03T17:00:00.000Z'),
      signatureExpiresAt: new Date('2026-11-04T18:00:00.000Z'),
    })
    const proof = await customHolderProof({
      key: x.holderKeys.privateKey, nonce: x.request.nonce,
      audience: AUDIENCE, credentialJwt: weaker.value,
    })
    expect(await x.verifier.verify({
      nonce: x.request.nonce, credentialJwt: weaker.value, holderProofJwt: proof,
    })).toEqual({ status: 'not_satisfied', reason: 'policy_not_met' })
  })

  test('rejects unsupported chain as not satisfying requested policy', async () => {
    const x = await setup({ chainId: 8453 })
    expect(await x.verifier.verify(x.presentation)).toEqual({
      status: 'not_satisfied', reason: 'policy_not_met',
    })
  })

  test('rejects wrong signed methodology version as policy_not_met', async () => {
    const x = await setup({ methodology: 'onchain-age/0.2.0' })
    expect(await x.verifier.verify(x.presentation)).toEqual({
      status: 'not_satisfied', reason: 'policy_not_met',
    })
  })

  test('rejects revoked credential', async () => {
    const x = await setup({ status: 'revoked' })
    expect(await x.verifier.verify(x.presentation)).toMatchObject({
      status: 'unverifiable', reason: 'credential_revoked',
    })
  })

  test('fails closed when status is unknown', async () => {
    const x = await setup({ status: 'unknown' })
    expect(await x.verifier.verify(x.presentation)).toMatchObject({
      status: 'unverifiable', reason: 'credential_status_unknown',
    })
  })

  test('fails closed if status provider throws', async () => {
    const x = await setup()
    x.statusChecker.check.mockRejectedValueOnce(new Error('status offline'))
    expect(await x.verifier.verify(x.presentation)).toMatchObject({
      status: 'unverifiable', reason: 'credential_status_unknown',
    })
  })

  test('refuses to start without status checker', async () => {
    const x = await setup()
    expect(() => new OnchainAgeVerifier({
      audience: AUDIENCE, policy: x.policy, store: x.store,
      statusChecker: undefined as never,
    })).toThrow('status checker')
  })

  test('will not accept credential by itself without holder signature', async () => {
    const x = await setup()
    expect(await x.verifier.verify({ ...x.presentation, holderProofJwt: '' })).toMatchObject({
      status: 'unverifiable', reason: 'invalid_holder_proof',
    })
  })

  test('integrates real OnchainAgeCredentialIssuer output with verifier', async () => {
    const x = await setup()
    const issuer = new OnchainAgeCredentialIssuer({
      issuer: ISSUER,
      signer: x.signer,
      evaluator: {
        async evaluate() {
          return {
            methodologyVersion: 'onchain-age/0.1.0' as const,
            status: 'satisfied' as const,
            thresholdDate: new Date(THRESHOLD),
            evidence: {
              hash: ('0x' + 'a'.repeat(64)) as Hex,
              blockNumber: 100n,
              transactionIndex: 0,
              timestamp: new Date('2023-11-01T00:00:00.000Z'),
            },
            coverage: {
              providerId: 'fixture',
              chainId: 1,
              fromBlock: 0n,
              throughBlock: 500n,
              fetchedAt: new Date(NOW),
              complete: true,
            },
          }
        },
      },
      clock: () => new Date(NOW),
    })
    const issued = await issuer.issue({
      ownership: {
        ok: true,
        address: '0x00000000000000000000000000000000000000A1' as Address,
        chainId: 1,
        verifiedAt: new Date(NOW.getTime() - 60_000),
      },
      thresholdDate: new Date(THRESHOLD),
      holderPublicJwk: x.holderPublicJwk,
    })
    expect(issued.status).toBe('issued')
    if (issued.status !== 'issued') return

    const request = await x.verifier.createRequest()
    const proof = await createHolderPresentation({
      credentialJwt: issued.credential.value,
      request,
      holderPrivateKey: x.holderKeys.privateKey,
      now: NOW,
    })
    expect((await x.verifier.verify(proof)).status).toBe('satisfied')
  })

  test('refuses a credential JWT issued implausibly far into the future', async () => {
    const x = await setup()
    const payload = decodeJwt(x.credential.value)
    const future = Math.floor(NOW.getTime() / 1000) + 3_600
    const crafted = await new SignJWT({ ...payload, iat: future })
      .setProtectedHeader({ alg: 'ES256', typ: 'vc+jwt', kid: KID })
      .setIssuer(ISSUER)
      .setIssuedAt(future)
      .setExpirationTime(future + 24 * 3_600)
      .sign(x.issuerKeys.privateKey)

    const holderProofJwt = await customHolderProof({
      key: x.holderKeys.privateKey,
      nonce: x.request.nonce,
      audience: AUDIENCE,
      credentialJwt: crafted,
    })
    expect(await x.verifier.verify({
      nonce: x.request.nonce, holderProofJwt, credentialJwt: crafted,
    })).toMatchObject({ status: 'unverifiable', reason: 'invalid_credential' })
  })

  test('invalid same-verifier proof burns nonce; next challenge is required', async () => {
    const x = await setup()
    const invalid = { ...x.presentation, holderProofJwt: 'invalid' }
    expect((await x.verifier.verify(invalid)).status).toBe('unverifiable')
    expect(await x.verifier.verify(x.presentation)).toMatchObject({
      status: 'unverifiable', reason: 'challenge_not_found_or_consumed',
    })
    const retry = await x.verifier.createRequest()
    const fresh = await createHolderPresentation({
      credentialJwt: x.credential.value, request: retry,
      holderPrivateKey: x.holderKeys.privateKey, now: NOW,
    })
    expect((await x.verifier.verify(fresh)).status).toBe('satisfied')
  })
})
