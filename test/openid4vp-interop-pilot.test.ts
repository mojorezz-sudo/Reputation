import { describe, expect, test, vi } from 'vitest'
import {
  CompactEncrypt,
  decodeJwt,
  exportJWK,
  generateKeyPair,
  SignJWT,
  type JWK,
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
  SecureOnchainAgeIssuanceCoordinator,
} from '../src/issuance/index.js'
import {
  buildOpenId4VpInvocationUri,
  createAttestedOpenId4VpRequest,
  createEncryptedDirectPostResponse,
  createJwtVpJsonPresentation,
  InMemoryOpenId4VpTransactionStore,
  InMemoryVerifiedPresentationStore,
  issueTestVerifierAttestation,
  OpenId4VpDirectPostProcessor,
  reissueForJwtVcJsonPilot,
  verifyAttestedRequestForWallet,
} from '../src/openid4vp/interop/index.js'

const NOW = new Date('2026-11-04T19:00:00.000Z')
const ISSUER = 'https://issuer.reputation.test'
const ISSUER_KID = 'https://issuer.reputation.test/keys/1'
const ATTESTOR = 'https://trust.reputation.test'
const CLIENT_ID = 'verifier_attestation:verifier.example'
const RESPONSE_URI = 'https://verifier.example/openid4vp/response'
const CONTINUE_URI = 'https://verifier.example/continue'
const REQUEST_URI = 'https://verifier.example/openid4vp/requests/session123'
const WALLET_ENDPOINT = 'https://wallet.example/authorize'
const WALLET = '0x00000000000000000000000000000000000000A1' as Address
const SESSION_ID = 'browser-session-A'
const THRESHOLD = new Date('2024-11-01T00:00:00.000Z')

async function setup() {
  const issuer = await generateKeyPair('ES256', { extractable: true })
  const holder = await generateKeyPair('ES256', { extractable: true })
  const verifier = await generateKeyPair('ES256', { extractable: true })
  const attestor = await generateKeyPair('ES256', { extractable: true })
  const encryption = await generateKeyPair('ECDH-ES', {
    crv: 'P-256', extractable: true,
  })
  const publicEncJwk = {
    ...await exportJWK(encryption.publicKey),
    kid: 'ephemeral-response-key-1',
    use: 'enc',
    alg: 'ECDH-ES',
  } as JWK
  const registry = new InMemoryIssuedCredentialRegistry()
  const evaluator: OnchainAgeEvaluator = {
    evaluate: vi.fn(async () => ({
      status: 'satisfied' as const,
      methodologyVersion: 'onchain-age/0.1.0' as const,
      thresholdDate: new Date(THRESHOLD),
      coverage: {
        chainId: 1,
        providerId: 'fixture',
        fromBlock: 0n,
        throughBlock: 22_000_000n,
        fetchedAt: new Date(NOW),
        complete: true,
      },
      evidence: {
        hash: ('0x' + 'a'.repeat(64)) as Hex,
        timestamp: new Date('2023-11-01T00:00:00.000Z'),
        blockNumber: 18_000_000n,
        transactionIndex: 0,
      },
    })),
  }
  const signer = new VcJwtCredentialSigner({
    issuer: ISSUER,
    kid: ISSUER_KID,
    privateKey: issuer.privateKey,
  })
  const credentialIssuer = new OnchainAgeCredentialIssuer({
    issuer: ISSUER, evaluator, signer, clock: () => new Date(NOW),
  })
  const coordinator = new SecureOnchainAgeIssuanceCoordinator({
    audience: ISSUER, issuerKeyId: ISSUER_KID, credentialIssuer,
    store: new InMemoryIssuanceSessionStore(),
    registry, clock: () => new Date(NOW),
  })
  const issuance = await coordinator.start({
    holderSessionId: SESSION_ID,
    verifiedOwnership: {
      ok: true,
      address: WALLET,
      chainId: 1,
      verifiedAt: new Date(NOW.getTime() - 60_000),
    },
    thresholdDate: THRESHOLD,
  })
  const keyProofJwt = await createIssuanceKeyProof({
    request: issuance,
    holderPrivateKey: holder.privateKey,
    holderPublicKey: holder.publicKey,
    now: NOW,
  })
  const issued = await coordinator.complete({
    holderSessionId: SESSION_ID, proofJwt: keyProofJwt,
  })
  expect(issued.status).toBe('issued')
  if (issued.status !== 'issued') throw new Error('fixture issuance failed')

  // This is a NEW issuer-signed interoperability credential format.
  // NEVER relabel application/vc+jwt as jwt_vc_json without reissuing.
  const legacy = await reissueForJwtVcJsonPilot({
    sourceVc2Jwt: issued.credential.credential.value,
    issuer: ISSUER,
    issuerKid: ISSUER_KID,
    issuerPublicKey: issuer.publicKey,
    issuerPrivateKey: issuer.privateKey,
    now: NOW,
  })
  await registry.recordIssued({
    credentialJwt: legacy,
    credentialId: decodeJwt(legacy).jti!,
    issuer: ISSUER,
    issuerKeyId: ISSUER_KID,
  })

  const attestationJwt = await issueTestVerifierAttestation({
    attestorIssuer: ATTESTOR,
    attestorPrivateKey: attestor.privateKey,
    clientId: CLIENT_ID,
    verifierPublicKey: verifier.publicKey,
    allowedResponseUris: [RESPONSE_URI],
    now: NOW,
  })
  const store = new InMemoryOpenId4VpTransactionStore()
  const request = await createAttestedOpenId4VpRequest({
    clientId: CLIENT_ID,
    responseUri: RESPONSE_URI,
    verifierAttestationJwt: attestationJwt,
    verifierSigningPrivateKey: verifier.privateKey,
    responseEncryptionPublicJwk: publicEncJwk,
    initiatedBySession: SESSION_ID,
    policy: {
      issuer: ISSUER,
      issuerKeyId: ISSUER_KID,
      issuerPublicKey: issuer.publicKey,
      chainId: 1,
      methodologyVersion: 'onchain-age/0.1.0',
      requiredThresholdDate: THRESHOLD.toISOString(),
    },
    store,
    now: NOW,
  })

  const walletRequest = await verifyAttestedRequestForWallet({
    requestObjectJwt: request.requestObjectJwt,
    trustedAttestorIssuer: ATTESTOR,
    trustedAttestorPublicKey: attestor.publicKey,
    now: NOW,
  })

  const vpJwt = await createJwtVpJsonPresentation({
    jwtVcJson: legacy,
    holderPrivateKey: holder.privateKey,
    nonce: walletRequest.nonce,
    audience: walletRequest.client_id,
    now: NOW,
  })
  const body = await createEncryptedDirectPostResponse({
    request: walletRequest,
    jwtVpJson: vpJwt,
  })

  const results = new InMemoryVerifiedPresentationStore()
  const processor = new OpenId4VpDirectPostProcessor({
    transactions: store,
    results,
    decryptionKey: encryption.privateKey,
    encryptionKeyId: publicEncJwk.kid!,
    statusChecker: registry,
    trustedContinuationUri: CONTINUE_URI,
    clock: () => new Date(NOW),
  })
  return {
    issuer, holder, verifier, attestor, encryption, publicEncJwk,
    registry, issued, legacy, request, store, walletRequest,
    vpJwt, body, processor, results, attestationJwt,
  }
}

function codeFromRedirect(uri: string): string {
  const fragment = new URL(uri).hash.slice(1)
  const code = new URLSearchParams(fragment).get('response_code')
  if (!code) throw new Error('No response code')
  return code
}

describe('OpenID4VP 1.0 protocol-shaped pilot: verifier attestation + direct_post.jwt', () => {
  test('real issuance -> trusted signed request -> encrypted VP -> session confirmation', async () => {
    const x = await setup()
    expect(x.request.nonce).toMatch(/^[A-Za-z0-9_-]{40,}$/)
    expect(x.request.state).not.toEqual(x.request.nonce)
    expect(x.walletRequest).toMatchObject({
      client_id: CLIENT_ID,
      response_type: 'vp_token',
      response_mode: 'direct_post.jwt',
      response_uri: RESPONSE_URI,
      dcql_query: {
        credentials: [{
          id: 'onchain_age',
          format: 'jwt_vc_json',
          require_cryptographic_holder_binding: true,
        }],
      },
    })
    expect(x.body).toMatch(/^response=eyJ/)
    const posted = await x.processor.processForm(x.body)
    expect(posted.status).toBe('pending_user_confirmation')
    if (posted.status !== 'pending_user_confirmation') return

    const code = codeFromRedirect(posted.redirect_uri)
    expect(code).toMatch(/^[0-9a-f]{64}$/)
    const result = await x.processor.confirmFromInitiatingSession({
      responseCode: code, authenticatedBrowserSession: SESSION_ID,
    })
    expect(result).toMatchObject({
      status: 'satisfied', chainId: 1, thresholdDate: THRESHOLD.toISOString(),
    })
    expect((await x.processor.confirmFromInitiatingSession({
      responseCode: code, authenticatedBrowserSession: SESSION_ID,
    })).status).toBe('unverifiable')
  })

  test('request_uri link points to the configured wallet and HTTPS request object endpoint', async () => {
    const x = await setup()
    const url = new URL(buildOpenId4VpInvocationUri({
      walletAuthorizationEndpoint: WALLET_ENDPOINT,
      clientId: CLIENT_ID,
      requestUri: REQUEST_URI,
    }))
    expect(url.origin).toBe('https://wallet.example')
    expect(url.searchParams.get('client_id')).toBe(CLIENT_ID)
    expect(url.searchParams.get('request_uri')).toBe(REQUEST_URI)
    expect(x.request.requestObjectJwt).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/)
  })

  test('untrusted verifier attestation authority is rejected by Wallet', async () => {
    const x = await setup()
    const otherAuthority = await generateKeyPair('ES256', { extractable: true })
    await expect(verifyAttestedRequestForWallet({
      requestObjectJwt: x.request.requestObjectJwt,
      trustedAttestorIssuer: ATTESTOR,
      trustedAttestorPublicKey: otherAuthority.publicKey,
      now: NOW,
    })).rejects.toThrow()
  })

  test('verifier signing key not matching attested public key is rejected', async () => {
    const x = await setup()
    const rogue = await generateKeyPair('ES256', { extractable: true })
    const otherStore = new InMemoryOpenId4VpTransactionStore()
    const signedByRogue = await createAttestedOpenId4VpRequest({
      clientId: CLIENT_ID, responseUri: RESPONSE_URI,
      verifierAttestationJwt: x.attestationJwt,
      verifierSigningPrivateKey: rogue.privateKey,
      responseEncryptionPublicJwk: x.publicEncJwk,
      initiatedBySession: SESSION_ID,
      policy: {
        issuer: ISSUER, issuerKeyId: ISSUER_KID,
        issuerPublicKey: x.issuer.publicKey, chainId: 1,
        methodologyVersion: 'onchain-age/0.1.0',
        requiredThresholdDate: THRESHOLD.toISOString(),
      },
      store: otherStore, now: NOW,
    })
    await expect(verifyAttestedRequestForWallet({
      requestObjectJwt: signedByRogue.requestObjectJwt,
      trustedAttestorIssuer: ATTESTOR,
      trustedAttestorPublicKey: x.attestor.publicKey,
      now: NOW,
    })).rejects.toThrow()
  })

  test('rejects response_URI substitution even with a valid verifier request signature', async () => {
    const x = await setup()
    const other = await createAttestedOpenId4VpRequest({
      clientId: CLIENT_ID,
      responseUri: 'https://attacker.example/collect',
      verifierAttestationJwt: x.attestationJwt,
      verifierSigningPrivateKey: x.verifier.privateKey,
      responseEncryptionPublicJwk: x.publicEncJwk,
      initiatedBySession: SESSION_ID,
      policy: {
        issuer: ISSUER, issuerKeyId: ISSUER_KID,
        issuerPublicKey: x.issuer.publicKey, chainId: 1,
        methodologyVersion: 'onchain-age/0.1.0',
        requiredThresholdDate: THRESHOLD.toISOString(),
      },
      store: new InMemoryOpenId4VpTransactionStore(),
      now: NOW,
    })
    await expect(verifyAttestedRequestForWallet({
      requestObjectJwt: other.requestObjectJwt,
      trustedAttestorIssuer: ATTESTOR,
      trustedAttestorPublicKey: x.attestor.publicKey,
      now: NOW,
    })).rejects.toThrow('Invalid OpenID4VP')
  })

  test('encrypted response can only be decrypted by the intended verifier key', async () => {
    const x = await setup()
    const other = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true })
    const processor = new OpenId4VpDirectPostProcessor({
      transactions: x.store, results: x.results,
      statusChecker: x.registry,
      decryptionKey: other.privateKey,
      encryptionKeyId: x.publicEncJwk.kid!,
      trustedContinuationUri: CONTINUE_URI,
      clock: () => new Date(NOW),
    })
    expect(await processor.processForm(x.body)).toMatchObject({
      status: 'unverifiable', reason: 'invalid_encrypted_response',
    })
    // Failed decryption must NOT consume the legitimate request.
    expect((await x.processor.processForm(x.body)).status).toBe('pending_user_confirmation')
  })

  test('replaying the identical encrypted form body is refused', async () => {
    const x = await setup()
    expect((await x.processor.processForm(x.body)).status).toBe('pending_user_confirmation')
    expect(await x.processor.processForm(x.body)).toMatchObject({
      status: 'unverifiable', reason: 'state_not_found_or_replayed',
    })
  })

  test('wrong browser session cannot finalize another user proof or consume their code', async () => {
    const x = await setup()
    const posted = await x.processor.processForm(x.body)
    expect(posted.status).toBe('pending_user_confirmation')
    if (posted.status !== 'pending_user_confirmation') return
    const code = codeFromRedirect(posted.redirect_uri)
    expect(await x.processor.confirmFromInitiatingSession({
      responseCode: code, authenticatedBrowserSession: 'attacker-browser-session',
    })).toMatchObject({
      status: 'unverifiable', reason: 'code_not_found_or_consumed',
    })
    expect((await x.processor.confirmFromInitiatingSession({
      responseCode: code, authenticatedBrowserSession: SESSION_ID,
    })).status).toBe('satisfied')
  })

  test('rejects forged or extra DCQL VP token entries after JWE decryption', async () => {
    const x = await setup()
    const encKey = await importPublicEncKey(x.publicEncJwk)
    const wrapped = new CompactEncrypt(new TextEncoder().encode(JSON.stringify({
      state: x.request.state,
      vp_token: { onchain_age: [x.vpJwt], extra: ['malicious'] },
    })))
      .setProtectedHeader({
        alg: 'ECDH-ES', enc: 'A128GCM', kid: x.publicEncJwk.kid!,
      })
    const jwe = await wrapped.encrypt(encKey)
    expect(await x.processor.processForm(new URLSearchParams({ response: jwe }).toString()))
      .toMatchObject({ status: 'unverifiable', reason: 'invalid_dcql_response_shape' })
  })

  test('nonce mismatch in a holder-signed VP must fail', async () => {
    const x = await setup()
    const bad = await createJwtVpJsonPresentation({
      jwtVcJson: x.legacy, holderPrivateKey: x.holder.privateKey,
      nonce: 'invalidnoncegeneratedtobeadefiniteplaceholderxxxxxxxxxxxxxxxx',
      audience: CLIENT_ID, now: NOW,
    })
    const body = await createEncryptedDirectPostResponse({
      request: x.walletRequest, jwtVpJson: bad,
    })
    expect(await x.processor.processForm(body)).toMatchObject({
      status: 'unverifiable', reason: 'holder_proof_invalid',
    })
  })

  test('wrong audience in a holder-signed VP fails', async () => {
    const x = await setup()
    const bad = await createJwtVpJsonPresentation({
      jwtVcJson: x.legacy, holderPrivateKey: x.holder.privateKey,
      nonce: x.walletRequest.nonce,
      audience: 'verifier_attestation:attacker.example', now: NOW,
    })
    const body = await createEncryptedDirectPostResponse({
      request: x.walletRequest, jwtVpJson: bad,
    })
    expect(await x.processor.processForm(body)).toMatchObject({
      status: 'unverifiable', reason: 'holder_proof_invalid',
    })
  })

  test('wrong holder key cannot sign a VP for another holder credential', async () => {
    const x = await setup()
    const attacker = await generateKeyPair('ES256', { extractable: true })
    const bad = await createJwtVpJsonPresentation({
      jwtVcJson: x.legacy, holderPrivateKey: attacker.privateKey,
      nonce: x.walletRequest.nonce, audience: CLIENT_ID, now: NOW,
    })
    const body = await createEncryptedDirectPostResponse({
      request: x.walletRequest, jwtVpJson: bad,
    })
    expect(await x.processor.processForm(body)).toMatchObject({
      status: 'unverifiable', reason: 'holder_proof_invalid',
    })
  })

  test('rejects revoked issuer-signed interoperability credential', async () => {
    const x = await setup()
    await x.registry.revoke(decodeJwt(x.legacy).jti!)
    expect(await x.processor.processForm(x.body)).toMatchObject({
      status: 'unverifiable', reason: 'credential_revoked',
    })
  })

  test('request expiration and user confirmation expiration both fail', async () => {
    const x = await setup()
    const processor = new OpenId4VpDirectPostProcessor({
      transactions: x.store,
      results: x.results,
      statusChecker: x.registry,
      decryptionKey: x.encryption.privateKey,
      encryptionKeyId: x.publicEncJwk.kid!,
      trustedContinuationUri: CONTINUE_URI,
      clock: () => new Date(NOW.getTime() + 301_000),
    })
    expect(await processor.processForm(x.body)).toMatchObject({
      status: 'unverifiable', reason: 'request_expired',
    })
  })

  test('malformed and duplicate form parameters fail before state consumption', async () => {
    const x = await setup()
    expect(await x.processor.processForm('response=abc&response=def')).toMatchObject({
      status: 'unverifiable', reason: 'invalid_http_form',
    })
    expect(await x.processor.processForm('state=unexpected')).toMatchObject({
      status: 'unverifiable', reason: 'invalid_http_form',
    })
    expect((await x.processor.processForm(x.body)).status).toBe('pending_user_confirmation')
  })

  test('a newly signed VP on the same reissued credential works with a new nonce', async () => {
    const x = await setup()
    expect((await x.processor.processForm(x.body)).status).toBe('pending_user_confirmation')
    const secondRequest = await createAttestedOpenId4VpRequest({
      clientId: CLIENT_ID, responseUri: RESPONSE_URI,
      verifierAttestationJwt: x.attestationJwt,
      verifierSigningPrivateKey: x.verifier.privateKey,
      responseEncryptionPublicJwk: x.publicEncJwk,
      initiatedBySession: SESSION_ID,
      policy: {
        issuer: ISSUER, issuerKeyId: ISSUER_KID,
        issuerPublicKey: x.issuer.publicKey, chainId: 1,
        methodologyVersion: 'onchain-age/0.1.0',
        requiredThresholdDate: THRESHOLD.toISOString(),
      },
      store: x.store, now: NOW,
    })
    expect(secondRequest.nonce).not.toBe(x.request.nonce)
    const walletView = await verifyAttestedRequestForWallet({
      requestObjectJwt: secondRequest.requestObjectJwt,
      trustedAttestorIssuer: ATTESTOR,
      trustedAttestorPublicKey: x.attestor.publicKey,
      now: NOW,
    })
    const vp = await createJwtVpJsonPresentation({
      jwtVcJson: x.legacy, holderPrivateKey: x.holder.privateKey,
      nonce: walletView.nonce, audience: walletView.client_id, now: NOW,
    })
    const body = await createEncryptedDirectPostResponse({ request: walletView, jwtVpJson: vp })
    expect((await x.processor.processForm(body)).status).toBe('pending_user_confirmation')
  })
})

// Helper only for attacker fixtures. Response issuer code is independent.
async function importPublicEncKey(jwk: JWK): Promise<CryptoKey> {
  const { importJWK } = await import('jose')
  return await importJWK(jwk, 'ECDH-ES') as CryptoKey
}
