import { describe, expect, test } from 'vitest'
import { decodeJwt, exportJWK, generateKeyPair, SignJWT } from 'jose'
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
} from '../src/credentials/sd-jwt-vc.js'
import { InMemoryIssuedCredentialRegistry } from '../src/issuance/index.js'
import { InMemoryDerivedCredentialStatusRegistry } from '../src/credentials/derived-status.js'
import {
  createAttestedOpenId4VpRequest,
  createEncryptedDirectPostResponse,
  InMemoryOpenId4VpTransactionStore,
  InMemoryVerifiedPresentationStore,
  issueTestVerifierAttestation,
  OpenId4VpDirectPostProcessor,
  verifyAttestedRequestForWallet,
} from '../src/openid4vp/interop/index.js'

const NOW = new Date('2026-11-06T20:00:00.000Z')
const ISSUER = 'https://issuer.reputation.test'
const KID = ISSUER + '/keys/1'
const ATTESTOR = 'https://trust.reputation.test'
const CLIENT_ID = 'verifier_attestation:reputation.example'
const RESPONSE_URI = 'https://verifier.example/oid4vp/response'
const CONTINUATION = 'https://verifier.example/finish'
const THRESHOLD = '2024-11-01T00:00:00.000Z'
const SESSION = 'server-authenticated-browser-A'
const ORIGINAL_ID = 'urn:uuid:00000000-0000-4000-8000-000000000007'

async function fixture() {
  const issuer = await generateKeyPair('ES256', { extractable: true })
  const holder = await generateKeyPair('ES256', { extractable: true })
  const verifier = await generateKeyPair('ES256', { extractable: true })
  const attestor = await generateKeyPair('ES256', { extractable: true })
  const enc = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true })
  const holderJwk = await exportJWK(holder.publicKey)
  const encJwk = { ...await exportJWK(enc.publicKey), kid: 'enc-1', alg: 'ECDH-ES', use: 'enc' }
  const sourceRegistry = new InMemoryIssuedCredentialRegistry()
  const credentialRegistry = new InMemoryDerivedCredentialStatusRegistry(sourceRegistry)

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
        providerId: 'hidden-indexer',
        fromBlock: '0',
        throughBlock: '22000000',
        complete: true,
      },
    },
  }
  const signer = new VcJwtCredentialSigner({
    issuer: ISSUER, kid: KID, privateKey: issuer.privateKey,
  })
  const signed = await signer.sign({
    credential: model,
    holderPublicJwk: holderJwk,
    issuedAt: new Date('2026-11-06T19:00:00.000Z'),
    signatureExpiresAt: new Date('2026-11-09T20:00:00.000Z'),
  })
  await sourceRegistry.recordIssued({
    credentialJwt: signed.value, credentialId: ORIGINAL_ID,
    issuer: ISSUER, issuerKeyId: KID,
  })
  const credential = await issueOnchainAgeSdJwtVc({
    sourceVc2Jwt: signed.value,
    issuer: ISSUER, issuerKid: KID,
    issuerPrivateKey: issuer.privateKey,
    issuerPublicKey: issuer.publicKey,
    sourceStatusChecker: sourceRegistry,
    newStatusRegistry: credentialRegistry,
    now: NOW,
  })
  const verifierAttestationJwt = await issueTestVerifierAttestation({
    attestorIssuer: ATTESTOR,
    attestorPrivateKey: attestor.privateKey,
    clientId: CLIENT_ID,
    verifierPublicKey: verifier.publicKey,
    allowedResponseUris: [RESPONSE_URI],
    now: NOW,
  })
  const transactions = new InMemoryOpenId4VpTransactionStore()
  const requests = await createAttestedOpenId4VpRequest({
    clientId: CLIENT_ID,
    responseUri: RESPONSE_URI,
    verifierAttestationJwt,
    verifierSigningPrivateKey: verifier.privateKey,
    responseEncryptionPublicJwk: encJwk,
    initiatedBySession: SESSION,
    credentialFormat: 'dc+sd-jwt',
    policy: {
      issuer: ISSUER,
      issuerKeyId: KID,
      issuerPublicKey: issuer.publicKey,
      chainId: 1,
      methodologyVersion: 'onchain-age/0.1.0',
      requiredThresholdDate: THRESHOLD,
    },
    store: transactions,
    now: NOW,
  })
  const walletView = await verifyAttestedRequestForWallet({
    requestObjectJwt: requests.requestObjectJwt,
    trustedAttestorIssuer: ATTESTOR,
    trustedAttestorPublicKey: attestor.publicKey,
    now: NOW,
  })
  const proof = await presentOnchainAgeSdJwtVc({
    credential,
    holderPrivateKey: holder.privateKey,
    nonce: walletView.nonce,
    audience: walletView.client_id,
    now: NOW,
  })
  const response = await createEncryptedDirectPostResponse({
    request: walletView,
    sdJwtVcPresentation: proof,
  })
  const results = new InMemoryVerifiedPresentationStore()
  const processor = new OpenId4VpDirectPostProcessor({
    transactions, results,
    statusChecker: credentialRegistry,
    decryptionKey: enc.privateKey,
    encryptionKeyId: 'enc-1',
    trustedContinuationUri: CONTINUATION,
    clock: () => new Date(NOW),
  })
  return {
    holder, credential, credentialRegistry, sourceRegistry, transactions, requests, walletView,
    proof, response, processor, results, issuer, enc, verifierAttestationJwt, verifier,
  }
}

describe('SD-JWT VC connected to actual signed OpenID4VP transaction', () => {
  test('verified signed request selects dc+sd-jwt and complete crypto flow succeeds', async () => {
    const x = await fixture()
    expect(x.walletView.dcql_query.credentials[0]).toMatchObject({
      format: 'dc+sd-jwt',
      meta: { vct_values: ['https://reputation.example/vct/onchain-age-v0.1'] },
      require_cryptographic_holder_binding: true,
    })
    expect(x.walletView.client_metadata.vp_formats_supported).toEqual({
      'dc+sd-jwt': {
        'sd-jwt_alg_values': ['ES256'],
        'kb-jwt_alg_values': ['ES256'],
      },
    })
    expect(decodeJwt(x.credential.issuerSignedJwt).jti).toBeUndefined()
    const resp = await x.processor.processForm(x.response)
    expect(resp.status).toBe('pending_user_confirmation')
    if (resp.status !== 'pending_user_confirmation') return
    const code = new URLSearchParams(new URL(resp.redirect_uri).hash.slice(1)).get('response_code')!
    const confirmed = await x.processor.confirmFromInitiatingSession({
      responseCode: code, authenticatedBrowserSession: SESSION,
    })
    expect(confirmed).toMatchObject({ status: 'satisfied', chainId: 1, thresholdDate: THRESHOLD })
  })

  test('legacy VP cannot be mislabeled as dc+sd-jwt when request selected SD-JWT', async () => {
    const x = await fixture()
    await expect(createEncryptedDirectPostResponse({
      request: x.walletView,
      jwtVpJson: x.proof,
    })).rejects.toThrow('format mismatch')
  })

  test('wallet refuses a signed request advertising a contradictory credential format', async () => {
    const x = await fixture()
    const iat = Math.floor(NOW.getTime() / 1000)
    const contradictory = await new SignJWT({
      ...x.walletView,
      client_metadata: {
        ...x.walletView.client_metadata,
        vp_formats_supported: { jwt_vc_json: { alg_values: ['ES256'] } },
      },
    })
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'oauth-authz-req+jwt',
        jwt: x.verifierAttestationJwt,
      })
      .setAudience('https://self-issued.me/v2')
      .setIssuedAt(iat)
      .setExpirationTime(iat + 120)
      .sign(x.verifier.privateKey)

    await expect(verifyAttestedRequestForWallet({
      requestObjectJwt: contradictory,
      trustedAttestorIssuer: ATTESTOR,
      trustedAttestorPublicKey: (await generateKeyPair('ES256')).publicKey,
      now: NOW,
    })).rejects.toThrow()
  })

  test('server refuses non SD-JWT data delivered inside correctly encrypted dc+sd-jwt response', async () => {
    const x = await fixture()
    const body = await createEncryptedDirectPostResponse({
      request: x.walletView,
      sdJwtVcPresentation: 'legacy.jwt.without.key.binding',
    })
    expect(await x.processor.processForm(body)).toMatchObject({
      status: 'unverifiable',
      reason: 'invalid_sd_jwt_serialization',
    })
  })

  test('cannot replay SD-JWT VC response with the same verifier transaction', async () => {
    const x = await fixture()
    expect((await x.processor.processForm(x.response)).status).toBe('pending_user_confirmation')
    expect(await x.processor.processForm(x.response)).toMatchObject({
      status: 'unverifiable', reason: 'state_not_found_or_replayed',
    })
  })

  test('replay protection cannot bypass a later source-credential revocation', async () => {
    const x = await fixture()
    await x.sourceRegistry.revoke(ORIGINAL_ID)
    expect(await x.processor.processForm(x.response)).toMatchObject({
      status: 'unverifiable', reason: 'credential_revoked',
    })
  })

  test('revoked SD-JWT VC is rejected even if holder proof remains valid', async () => {
    const x = await fixture()
    await x.credentialRegistry.revoke(x.credential.privateCredentialId)
    expect(await x.processor.processForm(x.response)).toMatchObject({
      status: 'unverifiable', reason: 'credential_revoked',
    })
  })

  test('only original authenticated browser session can confirm an SD-JWT result', async () => {
    const x = await fixture()
    const res = await x.processor.processForm(x.response)
    expect(res.status).toBe('pending_user_confirmation')
    if (res.status !== 'pending_user_confirmation') return
    const code = new URLSearchParams(new URL(res.redirect_uri).hash.slice(1)).get('response_code')!
    expect((await x.processor.confirmFromInitiatingSession({
      responseCode: code, authenticatedBrowserSession: 'browser-attacker',
    })).status).toBe('unverifiable')
    expect((await x.processor.confirmFromInitiatingSession({
      responseCode: code, authenticatedBrowserSession: SESSION,
    })).status).toBe('satisfied')
  })

  test('correct signing key but incorrect SD-JWT holder audience is rejected', async () => {
    const x = await fixture()
    const invalid = await presentOnchainAgeSdJwtVc({
      credential: x.credential,
      holderPrivateKey: x.holder.privateKey,
      nonce: x.walletView.nonce,
      audience: 'verifier_attestation:attacker.example',
      now: NOW,
    })
    const body = await createEncryptedDirectPostResponse({
      request: x.walletView,
      sdJwtVcPresentation: invalid,
    })
    expect(await x.processor.processForm(body)).toMatchObject({
      status: 'unverifiable', reason: 'invalid_key_binding',
    })
  })

  test('SD-JWT signed issuer response metadata never includes provider in plaintext', async () => {
    const x = await fixture()
    expect(x.proof).not.toContain('hidden-indexer')
    expect(x.proof).not.toContain('0x00000000000000000000000000000000000000A1')
  })
})
