import { describe, expect, test, vi } from 'vitest'
import {
  createOpaqueRequestUri,
  handleDirectPostJwtHttp,
  serveOpenId4VpSignedRequest,
  type OpenId4VpDirectPostProcessor,
} from '../src/openid4vp/interop/index.js'

const NOW = new Date('2026-11-04T20:00:00.000Z')
const REQUEST_BASE = 'https://verifier.example/openid4vp/requests'

describe('OpenID4VP HTTP boundaries', () => {
  test('request_uri is unpredictable, HTTPS, and distinct for each request', () => {
    const first = new URL(createOpaqueRequestUri(REQUEST_BASE))
    const second = new URL(createOpaqueRequestUri(REQUEST_BASE))
    expect(first.origin).toBe('https://verifier.example')
    expect(first.pathname).toMatch(/^\/openid4vp\/requests\/[0-9a-f]{64}$/)
    expect(first.href).not.toBe(second.href)
    expect(first.search).toBe('')
    expect(first.hash).toBe('')
  })

  test('request_uri refuses HTTP and query/fragment credentials', () => {
    for (const invalid of [
      'http://verifier.example/requests',
      'https://verifier.example/requests?token=secret',
      'https://verifier.example/requests#fragment',
      'https://user:password@verifier.example/requests',
    ]) {
      expect(() => createOpaqueRequestUri(invalid)).toThrow()
    }
  })

  test('serves the exact signed Request Object with no-store and correct media type', () => {
    const path = '/openid4vp/requests/' + 'a'.repeat(64)
    const signed = 'header.payload.signature'
    const response = serveOpenId4VpSignedRequest({
      method: 'GET',
      requestPath: path,
      expectedPath: path,
      signedRequestObject: signed,
      expiresAt: NOW.getTime() + 5 * 60_000,
      now: NOW,
    })
    expect(response.status).toBe(200)
    expect(response.body).toBe(signed)
    expect(response.headers['Cache-Control']).toBe('no-store')
    expect(response.headers['Referrer-Policy']).toBe('no-referrer')
    expect(response.headers['Content-Type']).toBe('application/oauth-authz-req+jwt')
  })

  test('signed-request endpoint rejects method/path and expiry', () => {
    const path = '/openid4vp/requests/' + 'a'.repeat(64)
    const base = {
      requestPath: path,
      expectedPath: path,
      signedRequestObject: 'h.p.s',
      expiresAt: NOW.getTime() + 1000,
      now: NOW,
    }
    expect(serveOpenId4VpSignedRequest({ ...base, method: 'POST' }).status).toBe(405)
    expect(serveOpenId4VpSignedRequest({ ...base, method: 'GET', requestPath: '/other' }).status).toBe(404)
    expect(serveOpenId4VpSignedRequest({
      ...base, method: 'GET', now: new Date(NOW.getTime() + 1000),
    }).status).toBe(410)
  })

  test('direct_post.jwt accepts only POST form-urlencoded and avoids leaking failures', async () => {
    const processForm = vi.fn(async () => ({
      status: 'pending_user_confirmation' as const,
      redirect_uri: 'https://verifier.example/continue#response_code=test',
    }))
    const processor = { processForm } as unknown as OpenId4VpDirectPostProcessor
    const body = 'response=encrypted-jwe'

    const wrongMethod = await handleDirectPostJwtHttp({
      method: 'GET', contentType: 'application/x-www-form-urlencoded', body, processor,
    })
    expect(wrongMethod.status).toBe(405)
    const wrongType = await handleDirectPostJwtHttp({
      method: 'POST', contentType: 'application/json', body, processor,
    })
    expect(wrongType.status).toBe(415)
    expect(processForm).not.toHaveBeenCalled()

    const ok = await handleDirectPostJwtHttp({
      method: 'POST',
      contentType: 'application/x-www-form-urlencoded; charset=utf-8',
      body,
      processor,
    })
    expect(ok.status).toBe(200)
    expect(JSON.parse(ok.body)).toEqual({
      redirect_uri: 'https://verifier.example/continue#response_code=test',
    })
    expect(ok.headers['Cache-Control']).toBe('no-store')
    expect(processForm).toHaveBeenCalledExactlyOnceWith(body)
  })

  test('direct_post.jwt returns only generic error on invalid proof', async () => {
    const processor = {
      processForm: vi.fn(async () => ({
        status: 'unverifiable' as const,
        reason: 'private_issuer_key_detail_should_not_leak',
      })),
    } as unknown as OpenId4VpDirectPostProcessor
    const response = await handleDirectPostJwtHttp({
      method: 'POST',
      contentType: 'application/x-www-form-urlencoded',
      body: 'response=invalid',
      processor,
    })
    expect(response.status).toBe(400)
    expect(response.body).toBe('{"error":"invalid_request"}')
    expect(response.body).not.toContain('private_issuer')
  })
})
