import type {
  OwnershipChallenge,
  OwnershipChallengeStore,
} from './types.js'

/**
 * Development/test store only.
 *
 * `take` removes a challenge before signature verification so two concurrent
 * verification attempts cannot both succeed with the same nonce. An invalid
 * attempt therefore burns the challenge and the holder must request a new one.
 */
export class InMemoryOwnershipChallengeStore
  implements OwnershipChallengeStore
{
  readonly #challenges = new Map<string, OwnershipChallenge>()

  async save(challenge: OwnershipChallenge): Promise<void> {
    if (this.#challenges.has(challenge.nonce)) {
      throw new Error('Ownership challenge nonce collision')
    }

    this.#challenges.set(challenge.nonce, challenge)
  }

  async take(nonce: string): Promise<OwnershipChallenge | undefined> {
    const challenge = this.#challenges.get(nonce)
    if (!challenge) return undefined

    this.#challenges.delete(nonce)
    return challenge
  }
}
