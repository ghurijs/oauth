// @ghuri/oauth/rest — use strategies as REST authentication classes.
import type { RequestUser } from '@ghuri/core'
import { AuthenticationFailed } from '@ghuri/rest'
import type { Context } from 'hono'
import { runStrategy } from './authenticate'
import type { StrategyRef } from './strategy'

/**
 * A REST authentication class that runs strategies (usually `BearerStrategy` / `CustomStrategy`):
 * `authenticationClasses = [StrategyAuthentication(['api-key'])]`.
 */
export function StrategyAuthentication(refs: StrategyRef | StrategyRef[], opts: { header?: string } = {}) {
  return class StrategyAuthenticationClass {
    async authenticate(c: Context): Promise<[RequestUser, unknown] | null> {
      const result = await runStrategy(c, refs)
      switch (result.type) {
        case 'success':
          if (result.user?.isActive === false) throw new AuthenticationFailed('User inactive or deleted.')
          return [result.user, result.info ?? null]
        case 'error':
          throw result.error
        case 'fail':
          // All strategies passed: no credentials of this kind; let the next class try.
          if (result.strategy === undefined) return null
          throw new AuthenticationFailed(result.message)
        default:
          return null
      }
    }

    authenticateHeader(): string {
      return opts.header ?? 'Bearer'
    }
  }
}
