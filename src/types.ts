import type { Context } from 'hono'

/** A user as the strategies see it: whatever your user model is (usually `@ghuri/auth`'s `User`). */
export type StrategyUser = any

export type StrategyResult =
  | { type: 'success'; user: StrategyUser; info?: Record<string, unknown> }
  /** `challenge` becomes `WWW-Authenticate`; `message` the error shown or returned. */
  | { type: 'fail'; status?: number; challenge?: string; message?: string }
  | { type: 'redirect'; url: string; status?: number }
  /** Not for this strategy: try the next one. */
  | { type: 'pass' }
  | { type: 'error'; error: unknown }
  /** The strategy answered the request itself (e.g. "we sent you a link"). */
  | { type: 'response'; response: Response }

export interface AuthenticateOptions {
  successRedirect?: string
  failureRedirect?: string
  /** Go to the `next` kept across the round trip when it is safe, else here. */
  successReturnToOrRedirect?: string
  /** Log the user in with `@ghuri/auth` (default true). */
  session?: boolean
  /** What to answer on success: a session login (default), a JWT pair, or your own response. */
  respond?:
    | 'session'
    | 'jwt'
    | ((c: Context, user: StrategyUser, info?: Record<string, unknown>) => Response | Promise<Response>)
  /** Extra scopes for this request (OAuth strategies). */
  scope?: string[]
  /** Where to go after login (default: the `next` query parameter); kept across the OAuth round trip. */
  next?: string
  /** Extra values kept across the OAuth round trip, returned in `info.state`. */
  state?: Record<string, string>
}

/** Provider tokens from an OAuth token endpoint. */
export interface OAuthTokens {
  accessToken: string
  tokenType?: string
  refreshToken?: string
  /** Seconds, as sent by the provider. */
  expiresIn?: number
  /** Absolute expiry (ms since epoch), computed from `expiresIn`. */
  expiresAt?: number
  idToken?: string
  scope?: string
  raw: Record<string, unknown>
}

/** A user profile from an identity provider, normalized. */
export interface Profile {
  provider: string
  id: string
  email?: string
  emailVerified?: boolean
  username?: string
  name?: string
  firstName?: string
  lastName?: string
  avatarUrl?: string
  raw: Record<string, unknown>
}

/** A value, or a function of the Worker/Node env that returns it (`(env) => env.GITHUB_SECRET`). */
export type EnvValue<T> = T | ((env: Record<string, any>) => T)
