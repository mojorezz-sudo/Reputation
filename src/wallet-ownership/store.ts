import type {
  OwnershipChallenge,
  OwnershipChallengeStore,
} from './types.js'

/**
 * Development/test store only.
 *
 * `take` consumes a challenge only when the expected holder session matches.
 * This prevents a signed challenge from being attached to another profile and
 * avoids letting a different session burn the legitimate holder's challenge.
 *
 * Once a matching session consumes the challenge, it is removed before
 * signature verification so two concurrent verification attempts cannot both
 * succeed with the same nonce. An invalid same-session attempt therefore burns
 * the challenge and the holder must request a new one.
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

  async take(
    nonce: string,
    holderSessionId: string,
  ): Promise<OwnershipChallenge | undefined> {
    const challenge = this.#challenges.get(nonce)
    if (!challenge || challenge.holderSessionId !== holderSessionId) {
      return undefined
    }

    this.#challenges.delete(nonce)
    return challenge
  }
}
