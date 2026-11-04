import {
  type OpenId4VpDirectPostProcessor,
} from './response.js'

export type HttpResponse = Readonly<{
  status: number
  headers: Readonly<Record<string, string>>
  body: string
}>

const SECURE_HEADERS = Object.freeze({
  'Cache-Control': 'no-store',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
})

function text(status: number, body: string, contentType: string): HttpResponse {
  return {
    status,
    headers: { ...SECURE_HEADERS, 'Content-Type': contentType },
    body,
  }
}

/**
 * An opaque, high-entropy reference for the public request_uri path.
 * The calling HTTP service must persist the signed Request Object and its
 * expiry under this handle and MUST NOT expose private wallet identifiers.
 */
export function createOpaqueRequestUri(baseHttpsUrl: string): string {
  const url = new URL(baseHttpsUrl)
  if (url.protocol !== 'https:' || url.hash || url.search ||
      url.username || url.password) {
    throw new Error('Request URI base requires clean HTTPS URL')
  }
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  const id = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
  const path = url.pathname.replace(/\/$/, '') + '/' + id
  url.pathname = path
  return url.toString()
}

/**
 * Framework-independent GET response for a previously generated signed JAR
 * Request Object. A deployed router must match the opaque request URI and
 * return this content verbatim. This adapter deliberately does not expose
 * credentials or private holder session information.
 */
export function serveOpenId4VpSignedRequest(input: {
  method: string
  requestPath: string
  expectedPath: string
  signedRequestObject: string
  expiresAt: number
  now?: Date
}): HttpResponse {
  if (input.method !== 'GET') {
    return text(405, '', 'text/plain; charset=utf-8')
  }
  if (input.requestPath !== input.expectedPath ||
      !/^\/[A-Za-z0-9/_-]{20,}$/.test(input.expectedPath)) {
    return text(404, '', 'text/plain; charset=utf-8')
  }
  if (!Number.isFinite((input.now ?? new Date()).getTime()) ||
      (input.now ?? new Date()).getTime() >= input.expiresAt) {
    return text(410, '', 'text/plain; charset=utf-8')
  }
  if (input.signedRequestObject.length > 30_000 ||
      input.signedRequestObject.split('.').length !== 3) {
    return text(500, '', 'text/plain; charset=utf-8')
  }
  return text(
    200, input.signedRequestObject,
    'application/oauth-authz-req+jwt',
  )
}

/**
 * HTTP wrapper for the OpenID4VP direct_post.jwt response processor.
 * A Wallet sends UTF-8 application/x-www-form-urlencoded with response=JWE.
 * Error details are NOT returned verbatim to untrusted wallet callers.
 */
export async function handleDirectPostJwtHttp(input: {
  method: string
  contentType: string
  body: string
  processor: OpenId4VpDirectPostProcessor
}): Promise<HttpResponse> {
  if (input.method !== 'POST') {
    return text(405, JSON.stringify({ error: 'invalid_request' }), 'application/json')
  }
  if (!/^application\/x-www-form-urlencoded(?:\s*;\s*charset=utf-8)?$/i.test(input.contentType)) {
    return text(415, JSON.stringify({ error: 'invalid_request' }), 'application/json')
  }
  const result = await input.processor.processForm(input.body)
  if (result.status !== 'pending_user_confirmation') {
    return text(400, JSON.stringify({ error: 'invalid_request' }), 'application/json')
  }
  // OID4VP Section 8.2: HTTP 200 JSON after successful handling;
  // continuation URI contains a one-time code in its fragment.
  return text(200, JSON.stringify({ redirect_uri: result.redirect_uri }), 'application/json')
}
