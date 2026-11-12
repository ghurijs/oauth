// The authorization code flow as a strategy: start (redirect to the provider), callback (exchange, profile, verify).
import { getHost, isSecure, tryGetContext } from '@ghuri/core'
import type { Context } from 'hono'
import { OAuth2Client } from './client'
import { pkcePair, randomToken } from './crypto'
import { OAuthError } from './errors'
import { getJson } from './http'
import { type PendingFlow, savePending, takePending } from './state'
import { Strategy } from './strategy'
import type {
  AuthenticateOptions,
  EnvValue,
  OAuthTokens,
  Profile,
  StrategyResult,
  StrategyUser,
} from './types'

export type MaybePromise<T> = T | Promise<T>

/** Resolve a setting that may be a function of env (and async, for computed secrets). */
export async function envValue<T>(
  value: EnvValue<T> | ((env: Record<string, any>) => Promise<T>),
): Promise<T> {
  if (typeof value === 'function') {
    return (value as (env: Record<string, any>) => MaybePromise<T>)(tryGetContext()?.env ?? {})
  }
  return value
}

export interface VerifyParams {
  profile: Profile
  tokens: OAuthTokens
  c: Context
  /** The flow this callback belongs to: `next`, `extra` (per-request state). */
  flow: PendingFlow
}

export type VerifyResult =
  | StrategyUser
  | null
  | false
  | { user: StrategyUser; info?: Record<string, unknown> }
export type VerifyFunction = (params: VerifyParams) => Promise<VerifyResult>

export interface ProfileContext {
  c: Context
  getJson(url: string, init?: RequestInit): Promise<Record<string, any>>
  /** GET with `Authorization: Bearer <access token>`. */
  getJsonAuthed(url: string, init?: RequestInit): Promise<Record<string, any>>
}

export interface OAuth2StrategyOptions {
  /** Strategy and profile provider name (default `'oauth2'`). */
  name?: string
  authorizationURL: EnvValue<string>
  tokenURL: EnvValue<string>
  clientId: EnvValue<string>
  clientSecret?: EnvValue<string | undefined> | ((env: Record<string, any>) => Promise<string>)
  /** Path or absolute URL of the callback (default: the path of the current request). */
  callbackURL?: EnvValue<string>
  scope?: string[]
  scopeSeparator?: string
  /** PKCE with S256 (default true). */
  pkce?: boolean
  authorizationParams?: Record<string, string> | ((c: Context) => Record<string, string>)
  tokenAuth?: 'body' | 'basic'
  revocationURL?: EnvValue<string | undefined>
  /** Fetch the profile from this URL with the access token, unless `profile` is given. */
  userInfoURL?: EnvValue<string>
  /** Build the normalized profile from the tokens. */
  profile?: (tokens: OAuthTokens, ctx: ProfileContext) => Promise<Profile>
}

/** Map a typical userinfo document to a `Profile`. */
export function profileFromClaims(provider: string, raw: Record<string, any>): Profile {
  const id = raw.sub ?? raw.id ?? raw.user_id
  if (id === undefined || id === null)
    throw new OAuthError('The provider profile has no user id.', 'invalid_profile')
  const verified = raw.email_verified ?? raw.verified_email
  return {
    provider,
    id: String(id),
    email: typeof raw.email === 'string' ? raw.email : undefined,
    emailVerified: verified === undefined ? undefined : verified === true || verified === 'true',
    username: raw.preferred_username ?? raw.login ?? raw.username ?? raw.nickname ?? undefined,
    name: raw.name ?? undefined,
    firstName: raw.given_name ?? raw.first_name ?? undefined,
    lastName: raw.family_name ?? raw.last_name ?? undefined,
    avatarUrl: raw.picture ?? raw.avatar_url ?? undefined,
    raw,
  }
}

function origin(c: Context): string {
  const base = (tryGetContext()?.settings.OAUTH as any)?.CALLBACK_BASE_URL as string | undefined
  if (base) return base.replace(/\/+$/, '')
  return `${isSecure(c) ? 'https' : 'http'}://${getHost(c)}`
}

/**
 * OAuth 2.0 authorization code flow (with PKCE). Mount one view for both legs:
 * `path('login/acme/', authenticate('acme'))` — without `code` it redirects to the provider, with it it logs in.
 */
export class OAuth2Strategy extends Strategy {
  readonly name: string

  constructor(
    readonly options: OAuth2StrategyOptions,
    readonly verify: VerifyFunction,
  ) {
    super()
    this.name = options.name ?? 'oauth2'
  }

  async client(): Promise<OAuth2Client> {
    const o = this.options
    return new OAuth2Client({
      authorizationURL: await envValue(o.authorizationURL),
      tokenURL: await envValue(o.tokenURL),
      clientId: await envValue(o.clientId),
      clientSecret: o.clientSecret === undefined ? undefined : await envValue(o.clientSecret),
      tokenAuth: o.tokenAuth,
      revocationURL: o.revocationURL === undefined ? undefined : await envValue(o.revocationURL),
      scopeSeparator: o.scopeSeparator,
    })
  }

  async callbackUrl(c: Context): Promise<string> {
    const configured =
      this.options.callbackURL === undefined ? undefined : await envValue(this.options.callbackURL)
    if (configured && /^https?:\/\//i.test(configured)) return configured
    return `${origin(c)}${configured ?? c.req.path}`
  }

  /** Extra authorization parameters and flow fields; OIDC adds a nonce. */
  protected async startExtras(_c: Context): Promise<{ params?: Record<string, string>; nonce?: string }> {
    return {}
  }

  protected scopes(options: AuthenticateOptions): string[] {
    return [...new Set([...(this.options.scope ?? []), ...(options.scope ?? [])])]
  }

  async authenticate(c: Context, options: AuthenticateOptions): Promise<StrategyResult> {
    const q = c.req.query()
    if (q.error) {
      await takePending(c, q.state)
      const message =
        q.error === 'access_denied' ? 'You cancelled the login.' : q.error_description || q.error
      return { type: 'fail', status: 401, message }
    }
    if (q.code) return this.callback(c, q.code, q.state)
    return this.start(c, options)
  }

  protected async start(c: Context, options: AuthenticateOptions): Promise<StrategyResult> {
    const client = await this.client()
    const state = randomToken(24)
    const pkce = this.options.pkce === false ? undefined : await pkcePair()
    const extras = await this.startExtras(c)
    const redirectUri = await this.callbackUrl(c)
    const next = options.next ?? c.req.query('next')
    await savePending(c, {
      state,
      strategy: this.name,
      redirectUri,
      verifier: pkce?.verifier,
      nonce: extras.nonce,
      next: next || undefined,
      extra: options.state,
      createdAt: Date.now(),
    })
    const ap = this.options.authorizationParams
    const params = { ...(typeof ap === 'function' ? ap(c) : (ap ?? {})), ...(extras.params ?? {}) }
    const url = client.authorizationUrl({
      redirectUri,
      state,
      scope: this.scopes(options),
      codeChallenge: pkce?.challenge,
      nonce: extras.nonce,
      params,
    })
    return { type: 'redirect', url, status: 302 }
  }

  protected async callback(c: Context, code: string, state: string | undefined): Promise<StrategyResult> {
    const flow = await takePending(c, state)
    if (!flow || flow.strategy !== this.name) {
      return {
        type: 'fail',
        status: 400,
        message: 'This login link expired or was already used. Please try again.',
      }
    }
    let tokens: OAuthTokens
    let profile: Profile
    try {
      const client = await this.client()
      tokens = await client.exchangeCode(code, flow.redirectUri, flow.verifier)
      profile = await this.userProfile(tokens, c, flow)
    } catch (err) {
      if (err instanceof OAuthError) return { type: 'fail', status: 401, message: err.message }
      throw err
    }
    const result = await this.verify({ profile, tokens, c, flow })
    if (!result) return { type: 'fail', status: 401, message: 'This account is not allowed to log in.' }
    const info = { profile, tokens, next: flow.next, state: flow.extra }
    if (
      typeof result === 'object' &&
      'user' in result &&
      Object.keys(result).every((k) => k === 'user' || k === 'info')
    ) {
      return { type: 'success', user: result.user, info: { ...info, ...(result.info ?? {}) } }
    }
    return { type: 'success', user: result, info }
  }

  protected profileContext(c: Context, tokens: OAuthTokens): ProfileContext {
    return {
      c,
      getJson,
      getJsonAuthed: (url, init = {}) => {
        const headers = new Headers(init.headers)
        headers.set('authorization', `Bearer ${tokens.accessToken}`)
        return getJson(url, { ...init, headers })
      },
    }
  }

  /** The normalized profile for these tokens. */
  async userProfile(tokens: OAuthTokens, c: Context, _flow?: PendingFlow): Promise<Profile> {
    const ctx = this.profileContext(c, tokens)
    if (this.options.profile) return this.options.profile(tokens, ctx)
    if (!this.options.userInfoURL) {
      throw new OAuthError(`Strategy '${this.name}' needs a userInfoURL or a profile() function.`)
    }
    return profileFromClaims(this.name, await ctx.getJsonAuthed(await envValue(this.options.userInfoURL)))
  }
}
