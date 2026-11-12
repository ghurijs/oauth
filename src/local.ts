// Username/password, magic links and bearer tokens.
import { authenticate as authAuthenticate, getUserModel, readData, saltedHmac } from '@ghuri/auth'
import { getHost, isSecure, tryGetContext, wantsJson } from '@ghuri/core'
import type { Context } from 'hono'
import { b64url, fromB64url, fromUtf8, timingSafeEqual, utf8 } from './crypto'
import { Strategy } from './strategy'
import type { AuthenticateOptions, StrategyResult, StrategyUser } from './types'

// ---- LocalStrategy ----

export interface LocalStrategyOptions {
  name?: string
  usernameField?: string
  passwordField?: string
}

export type LocalVerify = (params: {
  username: string
  password: string
  c: Context
}) => Promise<StrategyUser | null>

/**
 * Username and password from a JSON or form POST. The default `verify` is `@ghuri/auth`'s `authenticate()`, so
 * `AUTHENTICATION_BACKENDS`, password hashers and `userLoginFailed` all apply.
 */
export class LocalStrategy extends Strategy {
  readonly name: string
  private readonly usernameField: string
  private readonly passwordField: string

  constructor(
    options: LocalStrategyOptions = {},
    readonly verify: LocalVerify = ({ username, password, c }) => authAuthenticate(c, { username, password }),
  ) {
    super()
    this.name = options.name ?? 'local'
    this.usernameField = options.usernameField ?? 'username'
    this.passwordField = options.passwordField ?? 'password'
  }

  async authenticate(c: Context): Promise<StrategyResult> {
    if (c.req.method !== 'POST') return this.pass()
    const data = await readData(c)
    const username = data[this.usernameField]
    const password = data[this.passwordField]
    if (typeof username !== 'string' || !username || typeof password !== 'string' || !password) {
      return this.fail('Missing credentials.', 400)
    }
    const user = await this.verify({ username, password, c })
    return user ? this.success(user) : this.fail('Invalid credentials.', 401)
  }
}

// ---- MagicLinkStrategy ----

export interface MagicLinkOptions {
  name?: string
  /** Deliver the link. Called only when `verify` found a user for the address. */
  send: (params: { email: string; url: string; user: StrategyUser; c: Context }) => Promise<void>
  /** Seconds a link stays valid (default 900). */
  maxAge?: number
  emailField?: string
  /** Where forms go after asking for a link (default: the same URL with `?sent=1`). */
  sentRedirect?: string
}

export type MagicLinkVerify = (params: { email: string; c: Context }) => Promise<StrategyUser | null>

const MAGIC_SALT = 'ghuri.oauth.MagicLinkStrategy'
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

function hashValue(user: any, ts: number): string {
  const lastLogin = user.lastLogin ? new Date(user.lastLogin).toISOString() : ''
  const emailField = (user.constructor?.getEmailFieldName?.() as string | undefined) ?? 'email'
  return `${user.pk}${user.password ?? ''}${lastLogin}${ts}${user[emailField] ?? ''}`
}

async function mac(user: any, ts: number, secret?: string): Promise<string> {
  return b64url(await saltedHmac(MAGIC_SALT, hashValue(user, ts), secret, 'sha256'))
}

/**
 * Passwordless login: `POST { email }` sends a link, `GET ?token=` logs in. Links expire after `maxAge` and stop
 * working after one login (the signature covers `lastLogin`) or a password/email change. The POST answers the
 * same whether or not the address has an account.
 */
export class MagicLinkStrategy extends Strategy {
  readonly name: string

  constructor(
    readonly options: MagicLinkOptions,
    readonly verify: MagicLinkVerify,
  ) {
    super()
    this.name = options.name ?? 'magic-link'
  }

  /** A login token for `user` (exposed for custom delivery). */
  async makeToken(user: any): Promise<string> {
    const ts = Math.floor(Date.now() / 1000)
    return `${b64url(utf8(String(user.pk)))}.${ts.toString(36)}.${await mac(user, ts)}`
  }

  async checkToken(token: string): Promise<StrategyUser | null> {
    const [pkPart, tsPart, sig] = token.split('.')
    if (!pkPart || !tsPart || !sig) return null
    const ts = Number.parseInt(tsPart, 36)
    if (
      !Number.isFinite(ts) ||
      Date.now() / 1000 - ts > (this.options.maxAge ?? 900) ||
      ts > Date.now() / 1000 + 60
    ) {
      return null
    }
    let pk: string
    try {
      pk = fromUtf8(fromB64url(pkPart))
    } catch {
      return null
    }
    const User = getUserModel()
    let value: unknown
    try {
      value = User._meta.pk.toPython(pk)
    } catch {
      return null
    }
    const user = await User.objects.filter({ pk: value }).first()
    if (!user) return null
    const secrets = [
      undefined,
      ...((tryGetContext()?.settings.SECRET_KEY_FALLBACKS as string[] | undefined) ?? []),
    ]
    for (const secret of secrets) {
      if (timingSafeEqual(await mac(user, ts, secret), sig)) return user
    }
    return null
  }

  async authenticate(c: Context, _options: AuthenticateOptions): Promise<StrategyResult> {
    if (c.req.method === 'POST') return this.request(c)
    const token = c.req.query('token')
    if (!token) return this.pass()
    const user = await this.checkToken(token)
    if (!user) return this.fail('This login link is invalid or has expired.', 400)
    return this.success(user, { next: c.req.query('next') || undefined })
  }

  private async request(c: Context): Promise<StrategyResult> {
    const data = await readData(c)
    const email = String(data[this.options.emailField ?? 'email'] ?? '').trim()
    if (!EMAIL_RE.test(email)) return this.fail('Enter a valid email address.', 400)
    const user = await this.verify({ email, c })
    if (user && user.isActive !== false) {
      const url = new URL(c.req.path, `${isSecure(c) ? 'https' : 'http'}://${getHost(c)}`)
      url.searchParams.set('token', await this.makeToken(user))
      const next = typeof data.next === 'string' ? data.next : c.req.query('next')
      if (next) url.searchParams.set('next', next)
      await this.options.send({ email, url: url.toString(), user, c })
    }
    const detail = 'If an account exists for that address, we sent it a login link.'
    if (wantsJson(c)) return { type: 'response', response: c.json({ detail }) }
    return { type: 'redirect', url: this.options.sentRedirect ?? `${c.req.path}?sent=1`, status: 302 }
  }
}

// ---- BearerStrategy ----

export type BearerVerify = (
  token: string,
  c: Context,
) => Promise<StrategyUser | null | { user: StrategyUser; info?: Record<string, unknown> }>

/** `Authorization: Bearer <token>` → `verify(token)`. No header → pass; unknown token → 401 with a challenge. */
export class BearerStrategy extends Strategy {
  readonly name: string
  private readonly realm: string

  constructor(
    readonly verify: BearerVerify,
    options: { name?: string; realm?: string } = {},
  ) {
    super()
    this.name = options.name ?? 'bearer'
    this.realm = options.realm ?? 'api'
  }

  async authenticate(c: Context): Promise<StrategyResult> {
    const header = c.req.header('authorization')
    if (!header) return this.pass()
    const m = /^Bearer\s+(\S+)\s*$/i.exec(header)
    if (!m) return this.pass()
    const result = await this.verify(m[1], c)
    if (!result) {
      return this.fail('Invalid token.', 401, `Bearer realm="${this.realm}", error="invalid_token"`)
    }
    if (
      typeof result === 'object' &&
      'user' in result &&
      Object.keys(result).every((k) => k === 'user' || k === 'info')
    ) {
      return this.success(result.user, result.info)
    }
    return this.success(result)
  }
}
