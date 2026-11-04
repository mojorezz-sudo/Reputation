/**
 * Only an audience-binding contract for two OpenID4VP 1.0 transports.
 * This module does NOT implement Authorization Request, DCQL, VP token,
 * wallet invocation, token-format verification or response processing.
 *
 * SECURITY: clientId and origin MUST come from trusted registration or
 * browser assertion, not arbitrary request headers or holder input.
 */
export type OpenId4VpAudienceBinding =
  | Readonly<{ transport: 'direct_post'; clientId: string; responseUri: string }>
  | Readonly<{ transport: 'dc_api'; trustedBrowserOrigin: string }>

function httpsUrl(text: string): URL {
  let parsed: URL
  try {
    parsed = new URL(text)
  } catch {
    throw new Error('Invalid OpenID4VP URL')
  }
  if (parsed.protocol !== 'https:' ||
      parsed.username !== '' || parsed.password !== '' ||
      parsed.hash !== '') {
    throw new Error('OpenID4VP URL must be HTTPS without userinfo or fragment')
  }
  return parsed
}

/**
 * For redirect_uri client identifier, the full prefixed client_id is the
 * presentation audience, not the bare URL.
 * For DC API the audience is "origin:" plus the trusted browser origin,
 * even for a signed OpenID4VP request.
 * OpenID4VP 1.0 Final §14.1.2, §5.9 and Appendix A.4.
 */
export function expectedOpenId4VpAudience(input: OpenId4VpAudienceBinding): string {
  if (input.transport === 'direct_post') {
    if (!input.clientId.startsWith('redirect_uri:') ||
        input.clientId.startsWith('origin:')) {
      throw new Error('Unsupported or untrusted OpenID4VP client identifier')
    }
    const redirect = input.clientId.slice('redirect_uri:'.length)
    const uri = httpsUrl(redirect)
    const response = httpsUrl(input.responseUri)
    if (uri.href !== response.href) {
      throw new Error('Response URI must match redirect_uri client identifier')
    }
    return input.clientId
  }

  const origin = httpsUrl(input.trustedBrowserOrigin)
  if (origin.origin !== input.trustedBrowserOrigin) {
    throw new Error('DC API audience requires the canonical browser origin')
  }
  return 'origin:' + input.trustedBrowserOrigin
}
