import { describe, expect, test } from 'vitest'
import type { Address } from 'viem'

import { EtherscanV2HistoryProvider } from '../src/chain-history/index.js'

const HOLDER = '0x00000000000000000000000000000000000000A1' as Address
const API_KEY = 'super-secret-test-key'

describe('Etherscan provider secret handling', () => {
  test('redacts the API key even when a provider error payload echoes it', async () => {
    const provider = new EtherscanV2HistoryProvider({
      apiKey: API_KEY,
      finalizedBlockProvider: {
        async getFinalizedBlockNumber() {
          return 21_000_000n
        },
      },
      httpGet: async () => ({
        status: '0',
        message: 'NOTOK',
        result: `debug echo ${API_KEY}`,
      }),
      requestIntervalMs: 0,
    })

    let caught: unknown
    try {
      await provider.getOutboundTransactions({ chainId: 1, address: HOLDER })
    } catch (error) {
      caught = error
    }

    expect(String(caught)).toContain('[REDACTED]')
    expect(String(caught)).not.toContain(API_KEY)
  })
})
