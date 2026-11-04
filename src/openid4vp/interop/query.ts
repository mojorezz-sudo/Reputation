import {
  ONCHAIN_AGE_CREDENTIAL_TYPE,
} from '../../credentials/types.js'
import {
  OID4VP_VC_FORMAT,
  OID4VP_VC_QUERY_ID,
  type OnchainAgeDcql,
} from './types.js'

/**
 * Narrow supported DCQL subset. Do not claim general-purpose DCQL support.
 * Paths are evaluated against the VC object, not the enclosing JWT.
 */
export function createOnchainAgeDcql(): OnchainAgeDcql {
  return {
    credentials: [{
      id: OID4VP_VC_QUERY_ID,
      format: OID4VP_VC_FORMAT,
      require_cryptographic_holder_binding: true,
      meta: { type_values: [['VerifiableCredential', ONCHAIN_AGE_CREDENTIAL_TYPE]] },
      claims: [
        { path: ['credentialSubject', 'primitive'], values: ['OnchainAge'] },
        { path: ['credentialSubject', 'chainId'] },
        { path: ['credentialSubject', 'thresholdDate'] },
      ],
    }],
  }
}

export function matchesSupportedOnchainAgeDcql(query: unknown): boolean {
  return JSON.stringify(query) === JSON.stringify(createOnchainAgeDcql())
}
