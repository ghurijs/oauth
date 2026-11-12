import { ImproperlyConfigured } from '@ghuri/core'
import type { Context } from 'hono'
import type { AuthenticateOptions, StrategyResult } from './types'

/**
 * A way to authenticate a request (Passport.js's `Strategy`). `authenticate()` returns what happened:
 * success, fail, redirect, pass (not for me), error, or a response of its own.
 */
export abstract class Strategy {
  abstract readonly name: string
  abstract authenticate(c: Context, options: AuthenticateOptions): Promise<StrategyResult>

  protected success(user: unknown, info?: Record<string, unknown>): StrategyResult {
    return { type: 'success', user, info }
  }
  protected fail(message?: string, status = 401, challenge?: string): StrategyResult {
    return { type: 'fail', message, status, challenge }
  }
  protected redirect(url: string, status = 302): StrategyResult {
    return { type: 'redirect', url, status }
  }
  protected pass(): StrategyResult {
    return { type: 'pass' }
  }
}

/** A one-off strategy from a function: `new CustomStrategy('header', async (c) => …)`. */
export class CustomStrategy extends Strategy {
  constructor(
    readonly name: string,
    private readonly fn: (
      c: Context,
      options: AuthenticateOptions,
    ) => Promise<StrategyResult> | StrategyResult,
  ) {
    super()
  }
  async authenticate(c: Context, options: AuthenticateOptions): Promise<StrategyResult> {
    return this.fn(c, options)
  }
}

const KEY = Symbol.for('ghuri.oauth.strategies')
const registry: Map<string, Strategy> = (() => {
  const g = globalThis as any
  if (!g[KEY]) g[KEY] = new Map<string, Strategy>()
  return g[KEY]
})()

/** The strategy registry (Passport's `passport.use()`). */
export const strategies = {
  use(name: string, strategy: Strategy): void {
    registry.set(name, strategy)
  },
  get(name: string): Strategy {
    const s = registry.get(name)
    if (!s) {
      throw new ImproperlyConfigured(
        `Unknown authentication strategy '${name}'. Register it with strategies.use('${name}', …).`,
      )
    }
    return s
  },
  has(name: string): boolean {
    return registry.has(name)
  },
  unuse(name: string): boolean {
    return registry.delete(name)
  },
  names(): string[] {
    return [...registry.keys()]
  },
}

/** A strategy instance or a registered name. */
export type StrategyRef = string | Strategy

export function resolveStrategy(ref: StrategyRef): Strategy {
  return typeof ref === 'string' ? strategies.get(ref) : ref
}
