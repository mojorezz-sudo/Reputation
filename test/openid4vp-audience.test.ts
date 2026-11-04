import { describe, expect, test } from 'vitest'
import { expectedOpenId4VpAudience } from '../src/openid4vp/index.js'

describe('OpenID4VP 1.0 audience binding contracts (not a full protocol implementation)', () => {
  test('direct_post uses the entire verifier client_id including redirect_uri prefix', () => {
    expect(expectedOpenId4VpAudience({
      transport: 'direct_post',
      clientId: 'redirect_uri:https://verifier.example.com/presentation',
      responseUri: 'https://verifier.example.com/presentation',
    })).toBe('redirect_uri:https://verifier.example.com/presentation')
  })

  test('Digital Credentials API uses browser origin prefixed with origin:', () => {
    expect(expectedOpenId4VpAudience({
      transport: 'dc_api', trustedBrowserOrigin: 'https://verifier.example.com',
    })).toBe('origin:https://verifier.example.com')
  })

  test('direct_post and DC API audiences are not interchangeable', () => {
    const direct = expectedOpenId4VpAudience({
      transport: 'direct_post',
      clientId: 'redirect_uri:https://verifier.example.com/presentation',
      responseUri: 'https://verifier.example.com/presentation',
    })
    const dcApi = expectedOpenId4VpAudience({
      transport: 'dc_api',
      trustedBrowserOrigin: 'https://verifier.example.com',
    })
    expect(direct).not.toBe(dcApi)
  })

  test('rejects response URI substitution or client ID prefix spoofing', () => {
    expect(() => expectedOpenId4VpAudience({
      transport: 'direct_post',
      clientId: 'redirect_uri:https://verifier.example.com/presentation',
      responseUri: 'https://attacker.example/steal',
    })).toThrow('must match')
    expect(() => expectedOpenId4VpAudience({
      transport: 'direct_post',
      clientId: 'origin:https://verifier.example.com',
      responseUri: 'https://verifier.example.com/presentation',
    })).toThrow('client identifier')
  })

  test('rejects malformed or attacker-controlled DC API origins', () => {
    for (const trustedBrowserOrigin of [
      'http://verifier.example.com',
      'https://verifier.example.com/steal',
      'https://user:secret@verifier.example.com',
      'https://verifier.example.com#fragment',
    ]) {
      expect(() => expectedOpenId4VpAudience({
        transport: 'dc_api', trustedBrowserOrigin,
      })).toThrow()
    }
  })
})
