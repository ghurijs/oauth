// `authenticate(names, options)`: turn strategies into a view (Passport's `passport.authenticate()`).
import { getBackends, isSafeRedirect, login, tokenPairForUser } from '@ghuri/auth'
import {
  getHost,
  ImproperlyConfigured,
  resolveUrl,
  tryGetContext,
  type ViewFunction,
  wantsJson,
} from '@ghuri/core'
import type { Context } from 'hono'
import { resolveStrategy, type StrategyRef } from './strategy'
import type { AuthenticateOptions, StrategyResult, StrategyUser } from './types'

export type NamedResult = StrategyResult & { strategy?: string }

/** Run strategies in order until one does not `pass`. All pass → fail 401. Thrown errors → `error`. */
export async function runStrategy(
  c: Context,
  refs: StrategyRef | StrategyRef[],
  options: AuthenticateOptions = {},
): Promise<NamedResult> {
  const list = Array.isArray(refs) ? refs : [refs]
  for (const ref of list) {
    const strategy = resolveStrategy(ref)
    let result: StrategyResult
    try {
      result = await strategy.authenticate(c, options)
    } catch (error) {
      result = { type: 'error', error }
    }
    if (result.type !== 'pass') return { ...result, strategy: strategy.name }
  }
  return { type: 'fail', status: 401, message: 'Authentication credentials were not provided.' }
}

/** The name `login()` stores in the session: the first configured backend that can load users. */
export function loginBackendName(): string {
  const backend = getBackends().find((b) => typeof b.getUser === 'function')
  if (!backend) {
    throw new ImproperlyConfigured(
      'AUTHENTICATION_BACKENDS has no backend with getUser(); strategies cannot log users in.',
    )
  }
  return backend.backendName
}

export function userInfo(user: any): Record<string, unknown> {
  const M = user?.constructor as { USERNAME_FIELD?: string; EMAIL_FIELD?: string } | undefined
  const out: Record<string, unknown> = { pk: user.pk }
  const uf = M?.USERNAME_FIELD ?? 'username'
  if (user[uf] !== undefined) out[uf] = user[uf]
  const ef = M?.EMAIL_FIELD ?? 'email'
  if (user[ef] !== undefined && ef !== uf) out[ef] = user[ef]
  return out
}

function loginRedirectUrl(): string {
  return resolveUrl(
    (tryGetContext()?.settings.LOGIN_REDIRECT_URL as string | undefined) ?? '/accounts/profile/',
  )
}

/** Log `user` in and answer as `options` say. Exposed for packages that run strategies themselves. */
export async function completeLogin(
  c: Context,
  user: StrategyUser,
  info: Record<string, unknown> | undefined,
  options: AuthenticateOptions,
): Promise<Response> {
  const respond = options.respond ?? 'session'
  const useSession = options.session ?? respond !== 'jwt'
  if (useSession) await login(c, user, loginBackendName())
  if (typeof respond === 'function') return respond(c, user, info)
  if (respond === 'jwt') return c.json({ ...(await tokenPairForUser(user)), user: userInfo(user) })

  const next = (info?.next as string | undefined) ?? c.req.query('next')
  const safeNext = isSafeRedirect(next, [getHost(c)]) ? next : undefined
  let target: string | undefined
  if (options.successReturnToOrRedirect !== undefined) target = safeNext ?? options.successReturnToOrRedirect
  else if (options.successRedirect !== undefined) target = options.successRedirect
  else target = safeNext
  if (!target && wantsJson(c)) return c.json({ user: userInfo(user) })
  return c.redirect(target ?? loginRedirectUrl(), 302)
}

export function failureResponse(
  c: Context,
  result: { status?: number; challenge?: string; message?: string },
  options: AuthenticateOptions,
): Response {
  const message = result.message ?? 'Authentication failed.'
  if (options.failureRedirect && !wantsJson(c)) {
    const url = new URL(options.failureRedirect, 'http://x')
    url.searchParams.set('error', message)
    return c.redirect(`${options.failureRedirect.split('?')[0]}${url.search}`, 302)
  }
  const headers: Record<string, string> = {}
  if (result.challenge) headers['WWW-Authenticate'] = result.challenge
  const status = (result.status ?? 401) as 400 | 401 | 403
  if (wantsJson(c) || !options.failureRedirect) return c.json({ detail: message }, status, headers)
  return c.text(message, status, headers)
}

/**
 * A view that runs the strategies: `path('login/github/', authenticate('github', { successRedirect: '/' }))`.
 * Several names are tried in order (the first that does not pass wins).
 */
export function authenticate(
  refs: StrategyRef | StrategyRef[],
  options: AuthenticateOptions = {},
): ViewFunction {
  const view: ViewFunction = async (c) => {
    const result = await runStrategy(c, refs, options)
    switch (result.type) {
      case 'redirect':
        return c.redirect(result.url, (result.status ?? 302) as 302)
      case 'response':
        return result.response
      case 'error':
        throw result.error
      case 'fail':
        return failureResponse(c, result, options)
      case 'success': {
        if (result.user?.isActive === false) {
          return failureResponse(c, { status: 401, message: 'This account is inactive.' }, options)
        }
        return completeLogin(c, result.user, result.info, options)
      }
      default:
        return failureResponse(c, { status: 401 }, options)
    }
  }
  return view
}
