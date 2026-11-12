// @ghuri/oauth/testing — a fake identity provider for tests (no network), and a helper that follows the round trip.
import { b64url, randomToken, sha256 } from './crypto'
import { setProviderFetch } from './http'
import { clearJwksCache, signJwt } from './jwt'
import { clearDiscoveryCache } from './oidc'

export interface MockProviderOptions {
  /** Base URL of the fake provider (default `https://provider.test`); its OIDC issuer. */
  issuer?: string
  /** Claims / userinfo document of the user who "logs in" (OIDC style: `sub`, `email`, …). */
  profile?: Record<string, any>
  /** Extra fields for token responses. */
  tokenResponse?: Record<string, unknown>
  /** Extra URLs answered for authenticated GETs (provider APIs such as `https://api.github.com/user`). */
  routes?: Record<string, unknown | ((req: Request) => unknown | Promise<unknown>)>
  /** Treat any token endpoint POST as this provider's (default true). */
  anyTokenEndpoint?: boolean
}

interface IssuedCode {
  clientId: string
  redirectUri: string
  nonce?: string
  challenge?: string
  scope: string[]
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } })
}

/**
 * ```ts
 * const provider = mockOAuthProvider({ profile: { sub: '42', email: 'ann@example.com', email_verified: true } })
 * const res = await followOAuth(client, '/login/acme/', provider)
 * provider.restore()
 * ```
 */
export class MockProvider {
  readonly issuer: string
  profile: Record<string, any>
  readonly requests: Array<{ method: string; url: string }> = []
  private readonly codes = new Map<string, IssuedCode>()
  private readonly accessTokens = new Set<string>()
  private keys?: Promise<{ privateKey: CryptoKey; jwk: JsonWebKey & { kid: string } }>

  constructor(readonly options: MockProviderOptions = {}) {
    this.issuer = (options.issuer ?? 'https://provider.test').replace(/\/+$/, '')
    this.profile = options.profile ?? {
      sub: '1',
      email: 'user@example.com',
      email_verified: true,
      name: 'Test User',
    }
    setProviderFetch((input, init) => this.handle(new Request(input as any, init)))
  }

  get endpoints() {
    return {
      authorization: `${this.issuer}/authorize`,
      token: `${this.issuer}/token`,
      userinfo: `${this.issuer}/userinfo`,
      jwks: `${this.issuer}/jwks`,
      revocation: `${this.issuer}/revoke`,
    }
  }

  private signingKey() {
    this.keys ??= (async () => {
      const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
        'sign',
        'verify',
      ])) as CryptoKeyPair
      const jwk = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as JsonWebKey
      return { privateKey: pair.privateKey, jwk: { ...jwk, kid: 'mock-1', use: 'sig', alg: 'ES256' } }
    })()
    return this.keys
  }

  /**
   * Act as the user approving the request at `authorizeUrl`: returns the callback URL (with `code` and `state`, or
   * `error=access_denied` when `deny`).
   */
  authorize(authorizeUrl: string, opts: { deny?: boolean } = {}): string {
    const u = new URL(authorizeUrl)
    const q = u.searchParams
    const redirectUri = q.get('redirect_uri')
    if (!redirectUri) throw new Error('The authorization URL has no redirect_uri.')
    const back = new URL(redirectUri)
    if (q.get('state')) back.searchParams.set('state', q.get('state')!)
    if (opts.deny) {
      back.searchParams.set('error', 'access_denied')
      return back.toString()
    }
    const code = randomToken(16)
    this.codes.set(code, {
      clientId: q.get('client_id') ?? '',
      redirectUri,
      nonce: q.get('nonce') ?? undefined,
      challenge: q.get('code_challenge') ?? undefined,
      scope: (q.get('scope') ?? '').split(/[ ,]+/).filter(Boolean),
    })
    back.searchParams.set('code', code)
    return back.toString()
  }

  private async tokenResponse(form: URLSearchParams): Promise<Response> {
    const code = form.get('code') ?? ''
    const issued = this.codes.get(code)
    if (!issued) return json({ error: 'invalid_grant', error_description: 'Unknown or used code.' }, 400)
    this.codes.delete(code)
    if (form.get('redirect_uri') !== issued.redirectUri)
      return json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' }, 400)
    if (issued.challenge) {
      const verifier = form.get('code_verifier') ?? ''
      if (b64url(await sha256(verifier)) !== issued.challenge) {
        return json({ error: 'invalid_grant', error_description: 'PKCE verification failed' }, 400)
      }
    }
    const accessToken = randomToken(16)
    this.accessTokens.add(accessToken)
    const body: Record<string, unknown> = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: randomToken(16),
      scope: issued.scope.join(' '),
      ...this.options.tokenResponse,
    }
    if (issued.scope.includes('openid')) {
      const now = Math.floor(Date.now() / 1000)
      const { privateKey } = await this.signingKey()
      body.id_token = await signJwt(
        {
          iss: this.issuer,
          aud: issued.clientId,
          iat: now,
          exp: now + 600,
          ...(issued.nonce ? { nonce: issued.nonce } : {}),
          ...this.profile,
          sub: String(this.profile.sub ?? this.profile.id),
        },
        privateKey,
        'ES256',
        { kid: 'mock-1' },
      )
    }
    return json(body)
  }

  private authed(req: Request): boolean {
    const m = /^Bearer\s+(\S+)$/i.exec(req.headers.get('authorization') ?? '')
    return !!m && this.accessTokens.has(m[1])
  }

  private async handle(req: Request): Promise<Response> {
    this.requests.push({ method: req.method, url: req.url })
    const url = req.url.split('?')[0]
    if (req.method === 'POST') {
      const form = new URLSearchParams(await req.text())
      if (url === `${this.issuer}/revoke`) return new Response(null, { status: 200 })
      if (
        url === this.endpoints.token ||
        (this.options.anyTokenEndpoint !== false && form.get('grant_type'))
      ) {
        if (form.get('grant_type') === 'refresh_token') {
          const accessToken = randomToken(16)
          this.accessTokens.add(accessToken)
          return json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600 })
        }
        return this.tokenResponse(form)
      }
    }
    if (url === `${this.issuer}/.well-known/openid-configuration`) {
      return json({
        issuer: this.issuer,
        authorization_endpoint: this.endpoints.authorization,
        token_endpoint: this.endpoints.token,
        userinfo_endpoint: this.endpoints.userinfo,
        jwks_uri: this.endpoints.jwks,
        revocation_endpoint: this.endpoints.revocation,
      })
    }
    if (url === this.endpoints.jwks) return json({ keys: [(await this.signingKey()).jwk] })
    const route = this.options.routes?.[url] ?? this.options.routes?.[req.url]
    if (route !== undefined || url === this.endpoints.userinfo) {
      if (!this.authed(req)) return json({ error: 'invalid_token' }, 401)
      const value =
        route === undefined ? this.profile : typeof route === 'function' ? await (route as any)(req) : route
      return value instanceof Response ? value : json(value)
    }
    return json({ error: 'not_found', url: req.url }, 404)
  }

  /** Stop intercepting provider requests and forget cached discovery documents and keys. */
  restore(): void {
    setProviderFetch(undefined)
    clearDiscoveryCache()
    clearJwksCache()
  }
}

export function mockOAuthProvider(options: MockProviderOptions = {}): MockProvider {
  clearDiscoveryCache()
  clearJwksCache()
  return new MockProvider(options)
}

interface TestClientLike {
  get(path: string, opts?: any): Promise<Response>
  post?(path: string, opts?: any): Promise<Response>
}

function pathOf(url: string): string {
  const u = new URL(url, 'http://testserver')
  return `${u.pathname}${u.search}`
}

/**
 * Run the redirect round trip with the core test client: request `startPath` (GET, or POST with `method`), approve
 * at the mock provider, then request the callback. Returns the callback's response.
 */
export async function followOAuth(
  client: TestClientLike,
  startPath: string,
  provider: MockProvider,
  opts: { deny?: boolean; method?: 'GET' | 'POST'; body?: Record<string, unknown> } = {},
): Promise<Response> {
  const start =
    opts.method === 'POST' && client.post
      ? await client.post(startPath, { form: opts.body ?? {} })
      : await client.get(startPath)
  const location = start.headers.get('location')
  if (start.status < 300 || start.status >= 400 || !location) {
    throw new Error(`Expected a redirect to the provider from ${startPath}, got ${start.status}.`)
  }
  return client.get(pathOf(provider.authorize(location, opts)))
}
