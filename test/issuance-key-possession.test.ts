import { describe, expect, test, vi } from 'vitest'
import {
  base64url,
  decodeJwt,
  exportJWK,
  generateKeyPair,
  SignJWT,
} from 'jose'
import type { Address, Hex } from 'viem'
import {
  OnchainAgeCredentialIssuer,
  VcJwtCredentialSigner,
  type OnchainAgeEvaluator,
} from '../src/credentials/index.js'
import {
  createIssuanceKeyProof,
  InMemoryIssuanceSessionStore,
  InMemoryIssuedCredentialRegistry,
  ISSUANCE_KEY_PROOF_TYPE,
  SecureOnchainAgeIssuanceCoordinator,
} from '../src/issuance/index.js'
import {
  createHolderPresentation,
  InMemoryPresentationChallengeStore,
  OnchainAgeVerifier,
} from '../src/verifier/index.js'

const ISSUER = 'https://issuer.reputation.test'
const KEY_ID = 'https://issuer.reputation.test/keys/sandbox-1'
const VERIFIER = 'https://app.example/verify'
const NOW = new Date('2026-11-04T19:00:00.000Z')
const THRESHOLD = new Date('2024-11-01T00:00:00.000Z')
const WALLET = '0x00000000000000000000000000000000000000A1' as Address
const SESSION = 'private-holder-session-1'

async function setup() {
  const issuerKeys = await generateKeyPair('ES256', { extractable: true })
  const holderKeys = await generateKeyPair('ES256', { extractable: true })
  const holderPublicJwk = await exportJWK(holderKeys.publicKey)
  const registry = new InMemoryIssuedCredentialRegistry()
  const store = new InMemoryIssuanceSessionStore()
  const evaluator: OnchainAgeEvaluator = {
    evaluate: vi.fn(async () => ({
      status: 'satisfied' as const,
      methodologyVersion: 'onchain-age/0.1.0' as const,
      thresholdDate: new Date(THRESHOLD),
      evidence: {
        hash: ('0x' + 'a'.repeat(64)) as Hex,
        blockNumber: 10n,
        transactionIndex: 0,
        timestamp: new Date('2023-11-01T00:00:00.000Z'),
      },
      coverage: {
        chainId: 1,
        fromBlock: 0n,
        throughBlock: 500n,
        providerId: 'fixture',
        fetchedAt: new Date(NOW),
        complete: true,
      },
    })),
  }
  const credentialIssuer = new OnchainAgeCredentialIssuer({
    issuer: ISSUER,
    evaluator,
    signer: new VcJwtCredentialSigner({
      issuer: ISSUER,
      kid: KEY_ID,
      privateKey: issuerKeys.privateKey,
    }),
    clock: () => new Date(NOW),
  })
  const coordinator = new SecureOnchainAgeIssuanceCoordinator({
    audience: ISSUER,
    issuerKeyId: KEY_ID,
    credentialIssuer,
    store,
    registry,
    clock: () => new Date(NOW),
  })
  const ownership = {
    ok: true as const,
    address: WALLET,
    chainId: 1,
    verifiedAt: new Date(NOW.getTime() - 60_000),
  }
  const request = await coordinator.start({
    holderSessionId: SESSION,
    verifiedOwnership: ownership,
    thresholdDate: THRESHOLD,
  })
  const proofJwt = await createIssuanceKeyProof({
    request,
    holderPrivateKey: holderKeys.privateKey,
    holderPublicKey: holderKeys.publicKey,
    now: NOW,
  })
  return {
    coordinator, issuerKeys, holderKeys, holderPublicJwk, evaluator,
    registry, store, ownership, request, proofJwt,
  }
}

describe('issuer holder-key proof and revocable credential identity', () => {
  test('requires a fresh holder-signed issuance nonce and signs unique jti', async () => {
    const x = await setup()
    expect(x.request.nonce).toMatch(/^[A-Za-z0-9_-]{40,}$/)
    const response = await x.coordinator.complete({ holderSessionId: SESSION, proofJwt: x.proofJwt })
    expect(response.status).toBe('issued')
    if (response.status !== 'issued') return
    const token = response.credential.credential.value
    const model = response.credential.model
    const payload = decodeJwt(token)
    expect(payload.issuer).toBe(ISSUER)
    expect(payload.jti).toEqual(model.id)
    expect(model.id).toMatch(/^urn:uuid:/)
    expect(payload.id).toBe(model.id)
    expect(payload.cnf).toMatchObject({ jwk: x.holderPublicJwk })
    expect(await x.registry.check({ credentialJwt: token, issuer: ISSUER, issuerKeyId: KEY_ID })).toBe('valid')
    expect(x.evaluator.evaluate).toHaveBeenCalledWith({
      chainId: 1, holderAddress: WALLET, thresholdDate: THRESHOLD,
    })
  })

  test('real issuer output is accepted by the verifier and revoked tokens are rejected', async () => {
    const x = await setup()
    const issued = await x.coordinator.complete({ holderSessionId: SESSION, proofJwt: x.proofJwt })
    expect(issued.status).toBe('issued')
    if (issued.status !== 'issued') return
    const verifier = new OnchainAgeVerifier({
      audience: VERIFIER,
      policy: {
        issuer: ISSUER,
        issuerKeyId: KEY_ID,
        issuerPublicKey: x.issuerKeys.publicKey,
        chainId: 1,
        methodologyVersion: 'onchain-age/0.1.0',
        requiredThresholdDate: THRESHOLD.toISOString(),
      },
      store: new InMemoryPresentationChallengeStore(),
      statusChecker: x.registry,
      clock: () => new Date(NOW),
    })
    const challenge = await verifier.createRequest()
    const presentation = await createHolderPresentation({
      credentialJwt: issued.credential.credential.value,
      holderPrivateKey: x.holderKeys.privateKey,
      request: challenge,
      now: NOW,
    })
    expect((await verifier.verify(presentation)).status).toBe('satisfied')
    expect(await x.registry.revoke(issued.credential.model.id!)).toBe(true)
    const challenge2 = await verifier.createRequest()
    const presentation2 = await createHolderPresentation({
      credentialJwt: issued.credential.credential.value,
      holderPrivateKey: x.holderKeys.privateKey,
      request: challenge2,
      now: NOW,
    })
    expect(await verifier.verify(presentation2)).toMatchObject({
      status: 'unverifiable',
      reason: 'credential_revoked',
    })
  })

  test('each issuance gets a different ID and nonce', async () => {
    const x = await setup()
    const first = await x.coordinator.complete({ holderSessionId: SESSION, proofJwt: x.proofJwt })
    const secondRequest = await x.coordinator.start({
      holderSessionId: SESSION, verifiedOwnership: x.ownership, thresholdDate: THRESHOLD,
    })
    const secondProof = await createIssuanceKeyProof({
      request: secondRequest,
      holderPrivateKey: x.holderKeys.privateKey,
      holderPublicKey: x.holderKeys.publicKey,
      now: NOW,
    })
    const second = await x.coordinator.complete({ holderSessionId: SESSION, proofJwt: secondProof })
    expect(first.status).toBe('issued')
    expect(second.status).toBe('issued')
    if (first.status === 'issued' && second.status === 'issued') {
      expect(first.credential.model.id).not.toBe(second.credential.model.id)
      expect(x.request.nonce).not.toBe(secondRequest.nonce)
    }
  })

  test('cannot replay an issuance key proof within the same holder session', async () => {
    const x = await setup()
    expect((await x.coordinator.complete({ holderSessionId: SESSION, proofJwt: x.proofJwt })).status).toBe('issued')
    expect(await x.coordinator.complete({ holderSessionId: SESSION, proofJwt: x.proofJwt })).toEqual({
      status: 'not_issued', reason: 'invalid_or_consumed_session',
    })
  })

  test('different session cannot consume the legitimate holder nonce', async () => {
    const x = await setup()
    expect(await x.coordinator.complete({
      holderSessionId: 'attacker-session',
      proofJwt: x.proofJwt,
    })).toMatchObject({ status: 'not_issued', reason: 'invalid_or_consumed_session' })
    expect((await x.coordinator.complete({
      holderSessionId: SESSION, proofJwt: x.proofJwt,
    })).status).toBe('issued')
  })

  test('concurrent completion succeeds at most once', async () => {
    const x = await setup()
    const results = await Promise.all([
      x.coordinator.complete({ holderSessionId: SESSION, proofJwt: x.proofJwt }),
      x.coordinator.complete({ holderSessionId: SESSION, proofJwt: x.proofJwt }),
    ])
    expect(results.filter(r => r.status === 'issued')).toHaveLength(1)
  })

  test('wrong issuer audience fails cryptographic verification', async () => {
    const x = await setup()
    const wrongAudienceProof = await createIssuanceKeyProof({
      request: { ...x.request, audience: 'https://attacker.example' },
      holderPrivateKey: x.holderKeys.privateKey,
      holderPublicKey: x.holderKeys.publicKey,
      now: NOW,
    })
    expect(await x.coordinator.complete({ holderSessionId: SESSION, proofJwt: wrongAudienceProof })).toEqual({
      status: 'not_issued', reason: 'invalid_key_proof',
    })
  })

  test('wrong holder key cannot sign proof for another key JWK', async () => {
    const x = await setup()
    const other = await generateKeyPair('ES256', { extractable: true })
    const invalid = await new SignJWT({ nonce: x.request.nonce })
      .setProtectedHeader({
        alg: 'ES256', typ: ISSUANCE_KEY_PROOF_TYPE,
        jwk: await exportJWK(x.holderKeys.publicKey),
      })
      .setAudience(ISSUER)
      .setIssuedAt(Math.floor(NOW.getTime() / 1000))
      .setExpirationTime(Math.floor(NOW.getTime() / 1000) + 60)
      .sign(other.privateKey)
    expect(await x.coordinator.complete({ holderSessionId: SESSION, proofJwt: invalid })).toEqual({
      status: 'not_issued', reason: 'invalid_key_proof',
    })
  })

  test('attacker cannot replace issuance nonce in a signed proof', async () => {
    const x = await setup()
    const other = await x.coordinator.start({
      holderSessionId: SESSION, verifiedOwnership: x.ownership, thresholdDate: THRESHOLD,
    })
    const malformed = await new SignJWT({ nonce: other.nonce })
      .setProtectedHeader({
        alg: 'ES256', typ: ISSUANCE_KEY_PROOF_TYPE,
        jwk: await exportJWK(x.holderKeys.publicKey),
      })
      .setAudience(ISSUER)
      .setIssuedAt(Math.floor(NOW.getTime() / 1000))
      .setExpirationTime(Math.floor(NOW.getTime() / 1000) + 60)
      .sign(x.holderKeys.privateKey)
    // Modifying the JWT breaks signature; verification must fail closed.
    const parts = malformed.split('.')
    const payload = JSON.parse(new TextDecoder().decode(base64url.decode(parts[1]!))) as Record<string, unknown>
    payload.nonce = x.request.nonce
    parts[1] = base64url.encode(JSON.stringify(payload))
    const mutated = parts.join('.')
    expect(await x.coordinator.complete({ holderSessionId: SESSION, proofJwt: mutated })).toMatchObject({
      status: 'not_issued',
    })
  })

  test('expired issuance session is refused', async () => {
    const x = await setup()
    const after = new SecureOnchainAgeIssuanceCoordinator({
      audience: ISSUER,
      issuerKeyId: KEY_ID,
      credentialIssuer: new OnchainAgeCredentialIssuer({
        issuer: ISSUER,
        signer: new VcJwtCredentialSigner({
          issuer: ISSUER, kid: KEY_ID, privateKey: x.issuerKeys.privateKey,
        }),
        evaluator: x.evaluator,
        clock: () => new Date(NOW.getTime() + 130_000),
      }),
      store: x.store,
      registry: x.registry,
      clock: () => new Date(NOW.getTime() + 130_000),
    })
    expect(await after.complete({ holderSessionId: SESSION, proofJwt: x.proofJwt })).toEqual({
      status: 'not_issued', reason: 'session_expired',
    })
  })

  test('revocation service fails closed for unregistered credentials', async () => {
    const x = await setup()
    expect(await x.registry.check({
      credentialJwt: 'untrusted.jwt',
      issuer: ISSUER,
      issuerKeyId: KEY_ID,
    })).toBe('unknown')
  })

  test('holder private JWK in proof is rejected', async () => {
    const x = await setup()
    const jwk = await exportJWK(x.holderKeys.privateKey)
    expect(jwk.d).toBeDefined()
    const withPrivateKey = await new SignJWT({ nonce: x.request.nonce })
      .setProtectedHeader({ alg: 'ES256', typ: ISSUANCE_KEY_PROOF_TYPE, jwk })
      .setAudience(ISSUER)
      .setIssuedAt(Math.floor(NOW.getTime() / 1000))
      .setExpirationTime(Math.floor(NOW.getTime() / 1000) + 60)
      .sign(x.holderKeys.privateKey)
    expect(await x.coordinator.complete({ holderSessionId: SESSION, proofJwt: withPrivateKey })).toEqual({
      status: 'not_issued', reason: 'invalid_key_proof',
    })
  })

  test('refuses stale or future-dated ownership record at session start', async () => {
    const x = await setup()
    await expect(x.coordinator.start({
      holderSessionId: SESSION,
      verifiedOwnership: {
        ...x.ownership,
        verifiedAt: new Date(NOW.getTime() - 20 * 60_000),
      },
      thresholdDate: THRESHOLD,
    })).rejects.toThrow('stale issuance')
    await expect(x.coordinator.start({
      holderSessionId: SESSION,
      verifiedOwnership: {
        ...x.ownership,
        verifiedAt: new Date(NOW.getTime() + 1000),
      },
      thresholdDate: THRESHOLD,
    })).rejects.toThrow('stale issuance')
  })

  test('issuer status registry scopes the lookup to issuer ID and key ID', async () => {
    const x = await setup()
    const done = await x.coordinator.complete({ holderSessionId: SESSION, proofJwt: x.proofJwt })
    expect(done.status).toBe('issued')
    if (done.status !== 'issued') return
    const token = done.credential.credential.value
    expect(await x.registry.check({
      credentialJwt: token, issuer: 'https://untrusted.example', issuerKeyId: KEY_ID,
    })).toBe('unknown')
    expect(await x.registry.check({
      credentialJwt: token, issuer: ISSUER, issuerKeyId: 'https://issuer.reputation.test/keys/forged',
    })).toBe('unknown')
  })

  test('refuses issuer key-ID configuration mismatch before status registry recording', async () => {
    const x = await setup()
    const signer = new VcJwtCredentialSigner({
      issuer: ISSUER, kid: KEY_ID, privateKey: x.issuerKeys.privateKey,
    })
    const coordinator = new SecureOnchainAgeIssuanceCoordinator({
      audience: ISSUER,
      issuerKeyId: 'https://issuer.reputation.test/keys/untrusted-other-key',
      credentialIssuer: new OnchainAgeCredentialIssuer({
        issuer: ISSUER,
        signer,
        evaluator: x.evaluator,
        clock: () => new Date(NOW),
      }),
      store: x.store,
      registry: x.registry,
      clock: () => new Date(NOW),
    })
    const request = await coordinator.start({
      holderSessionId: SESSION, verifiedOwnership: x.ownership, thresholdDate: THRESHOLD,
    })
    const proofJwt = await createIssuanceKeyProof({
      request,
      holderPrivateKey: x.holderKeys.privateKey,
      holderPublicKey: x.holderKeys.publicKey,
      now: NOW,
    })
    await expect(coordinator.complete({ holderSessionId: SESSION, proofJwt }))
      .rejects.toThrow('Issuer signing configuration')
  })
})
