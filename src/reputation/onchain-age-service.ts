import type { Address } from 'viem'

import type { ChainHistoryProvider } from '../chain-history/index.js'
import {
  evaluateOnchainAge,
  type OnchainAgeResult,
} from './onchain-age.js'

export type EvaluateWalletOnchainAgeInput = Readonly<{
  /**
   * This service assumes wallet control was verified by the ownership boundary
   * before invocation. It deliberately does not infer identity continuity.
   */
  holderAddress: Address
  chainId: number
  thresholdDate: Date
}>

/**
 * Thin application boundary that composes replaceable chain history with the
 * provider-neutral OnchainAge methodology.
 *
 * Provider/transport failures are not converted into reputation results. They
 * propagate as operational errors so callers cannot mistake an unavailable
 * data source for a trustworthy negative claim.
 */
export class OnchainAgeService {
  readonly #historyProvider: ChainHistoryProvider

  constructor(historyProvider: ChainHistoryProvider) {
    this.#historyProvider = historyProvider
  }

  async evaluate(
    input: EvaluateWalletOnchainAgeInput,
  ): Promise<OnchainAgeResult> {
    const history = await this.#historyProvider.getOutboundTransactions({
      chainId: input.chainId,
      address: input.holderAddress,
    })

    return evaluateOnchainAge({
      holderAddress: input.holderAddress,
      chainId: input.chainId,
      thresholdDate: input.thresholdDate,
      history,
    })
  }
}
