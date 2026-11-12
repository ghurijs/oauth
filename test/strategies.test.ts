// Strategies end to end through createApp + @ghuri/auth, against the mock provider.
import {
  AuthConfig,
  AuthenticationMiddleware,
  AuthTokenConfig,
  authUrls,
  ContentType,
  ContentTypesConfig,
  PBKDF2PasswordHasher,
  SessionMiddleware,
  SessionsConfig,
  User,
} from '@ghuri/auth'
import { CsrfMiddleware, createApp, defineSettings, type GhuriApp, include, path } from '@ghuri/core'
import { createTestClient, type TestClient } from '@ghuri/core/testing'
import { setupTestDatabase, type TestDatabase } from '@ghuri/orm/testing'
import { APIView, IsAuthenticated } from '@ghuri/rest'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import {
  authenticate,
  BearerStrategy,
  CustomStrategy,
  LocalStrategy,
  MagicLinkStrategy,
  OAuth2Strategy,
  OIDCStrategy,
  strategies,
} from '../src/index'
import { StrategyAuthentication } from '../src/rest'
import { followOAuth, type MockProvider, mockOAuthProvider } from '../src/testing'

const ISSUER = 'https://idp.test'
const sent: Array<{ email: string; url: string }> = []

async function userForProfile({ profile }: { profile: { email?: string; username?: string } }) {
  if (!profile.email) return null
  const existing = await User.objects.filter({ email: profile.email }).first()
  return existing ?? User.objects.createUser(profile.username ?? profile.email.split('@')[0], profile.email)
}

strategies.use(
  'acme',
  new OIDCStrategy(
    { name: 'acme', issuer: ISSUER, clientId: 'acme-client', clientSecret: (env) => env.ACME_SECRET },
    userForProfile,
  ),
)
strategies.use(
  'plain',
  new OAuth2Strategy(
    {
      name: 'plain',
      authorizationURL: `${ISSUER}/authorize`,
      tokenURL: `${ISSUER}/token`,
      userInfoURL: `${ISSUER}/me`,
      clientId: 'plain-client',
      clientSecret: 'plain-secret',
      tokenAuth: 'basic',
      scope: ['read'],
    },
    userForProfile,
  ),
)
strategies.use('local', new LocalStrategy())
strategies.use(
  'email',
  new MagicLinkStrategy(
    { send: async ({ email, url }) => void sent.push({ email, url }), maxAge: 60 },
    async ({ email }) => User.objects.filter({ email }).first(),
  ),
)
strategies.use(
  'api-key',
  new BearerStrategy(async (token) =>
    token === 'k-ann' ? User.objects.filter({ username: 'ann' }).first() : null,
  ),
)
strategies.use('never', new CustomStrategy('never', () => ({ type: 'pass' })))

class ApiMe extends APIView {
  override authenticationClasses = [StrategyAuthentication(['api-key'])]
  override permissionClasses = [IsAuthenticated]
  async get(request: any) {
    return { username: request.user.username }
  }
}

const urls = [
  path('accounts/', include(authUrls)),
  path('login/acme/', authenticate('acme', { failureRedirect: '/login/' })),
  path('login/plain/', authenticate('plain', { respond: 'jwt' })),
  path('login/local/', authenticate(['never', 'local'])),
  path('login/email/', authenticate('email', { successRedirect: '/welcome/' })),
  path('api/me/', ApiMe),
]

describe('@ghuri/oauth strategies', () => {
  let app: GhuriApp
  let db: TestDatabase
  let client: TestClient
  let provider: MockProvider
  const env = { ACME_SECRET: 'acme-secret' }

  beforeAll(async () => {
    app = createApp(
      defineSettings(() => ({
        SECRET_KEY: 'oauth-tests',
        ALLOWED_HOSTS: ['testserver'],
        INSTALLED_APPS: [ContentTypesConfig, AuthConfig, SessionsConfig, AuthTokenConfig],
        MIDDLEWARE: [SessionMiddleware, CsrfMiddleware, AuthenticationMiddleware],
        ROOT_URLCONF: urls,
        PASSWORD_HASHERS: [new PBKDF2PasswordHasher({ iterations: 1000 })],
        LOGIN_REDIRECT_URL: '/home/',
      })),
      { checks: false },
    )
    await app.setup(env)
    db = await setupTestDatabase({ using: 'sqlite' })
  }, 60_000)
  afterAll(async () => {
    await db?.teardown()
  })
  beforeEach(async () => {
    ContentType.objects.clearCache()
    await db.flush()
    ContentType.objects.clearCache()
    client = createTestClient(app, { env })
    sent.length = 0
    provider = mockOAuthProvider({
      issuer: ISSUER,
      profile: { sub: 'u-1', email: 'ann@example.com', email_verified: true, preferred_username: 'ann' },
      routes: { [`${ISSUER}/me`]: { id: 77, login: 'ann', email: 'ann@example.com' } },
    })
  })
  afterEach(() => provider.restore())

  const me = async () =>
    (await (await client.get('/accounts/me/', { headers: { accept: 'application/json' } })).json()) as any

  it('OIDC: redirects with state, nonce and PKCE, validates the ID token and logs in', async () => {
    const start = await client.get('/login/acme/?next=/dashboard/')
    expect(start.status).toBe(302)
    const auth = new URL(start.headers.get('location')!)
    expect(auth.origin + auth.pathname).toBe(`${ISSUER}/authorize`)
    for (const p of ['state', 'nonce', 'code_challenge']) expect(auth.searchParams.get(p)).toBeTruthy()
    expect(auth.searchParams.get('code_challenge_method')).toBe('S256')
    expect(auth.searchParams.get('scope')).toBe('openid email profile')
    expect(auth.searchParams.get('redirect_uri')).toBe('http://testserver/login/acme/')

    const callback = new URL(provider.authorize(auth.toString()))
    const done = await client.get(callback.pathname + callback.search)
    expect(done.status).toBe(302)
    expect(done.headers.get('location')).toBe('/dashboard/')
    expect(await me()).toMatchObject({ isAuthenticated: true, user: { username: 'ann' } })
    expect(provider.requests.some((r) => r.url === `${ISSUER}/jwks`)).toBe(true)
  })

  it('ignores unsafe next URLs and falls back to LOGIN_REDIRECT_URL', async () => {
    const res = await followOAuth(client, '/login/acme/?next=https://evil.example/', provider)
    expect(res.headers.get('location')).toBe('/home/')
  })

  it('rejects replayed or unknown state and denied consent', async () => {
    const start = await client.get('/login/acme/')
    const callback = new URL(provider.authorize(start.headers.get('location')!))
    const first = await client.get(callback.pathname + callback.search)
    expect(first.status).toBe(302)
    const replay = await client.get(callback.pathname + callback.search)
    expect(replay.status).toBe(302)
    expect(replay.headers.get('location')).toMatch(/^\/login\/\?error=/)
    const denied = await followOAuth(createTestClient(app, { env }), '/login/acme/', provider, { deny: true })
    const error = new URL(denied.headers.get('location')!, 'http://testserver').searchParams.get('error')
    expect(error).toBe('You cancelled the login.')
  })

  it('keeps two pending flows apart (two tabs)', async () => {
    const a = await client.get('/login/acme/?next=/a/')
    const b = await client.get('/login/acme/?next=/b/')
    const cbA = new URL(provider.authorize(a.headers.get('location')!))
    const cbB = new URL(provider.authorize(b.headers.get('location')!))
    expect((await client.get(cbB.pathname + cbB.search)).headers.get('location')).toBe('/b/')
    expect((await client.get(cbA.pathname + cbA.search)).headers.get('location')).toBe('/a/')
  })

  it('OAuth2 with a userinfo URL, basic client auth and a JWT response', async () => {
    const res = await followOAuth(client, '/login/plain/', provider)
    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    expect(body.user).toMatchObject({ username: 'ann', email: 'ann@example.com' })
    expect(typeof body.access).toBe('string')
    expect(typeof body.refresh).toBe('string')
    expect((await me()).isAuthenticated).toBe(false)
  })

  it('local strategy after a passing strategy', async () => {
    await User.objects.createUser('ann', 'ann@example.com', 'pw')
    const bad = await client.post('/login/local/', { json: { username: 'ann', password: 'nope' } })
    expect(bad.status).toBe(401)
    const missing = await client.post('/login/local/', { json: { username: 'ann' } })
    expect(missing.status).toBe(400)
    const ok = await client.post('/login/local/', { json: { username: 'ann', password: 'pw' } })
    expect(ok.status).toBe(200)
    expect(await ok.json()).toMatchObject({ user: { username: 'ann' } })
    expect((await me()).user.username).toBe('ann')
    expect((await client.get('/login/local/', { headers: { accept: 'application/json' } })).status).toBe(401)
  })

  it('magic links: same answer for unknown addresses, single use, expiry', async () => {
    await User.objects.createUser('ann', 'ann@example.com', 'pw')
    const json = { headers: { accept: 'application/json' } }
    const unknown = await client.post('/login/email/', { json: { email: 'nobody@example.com' }, ...json })
    const known = await client.post('/login/email/', { json: { email: 'ann@example.com' }, ...json })
    expect(await unknown.json()).toEqual(await known.json())
    expect(sent.map((s) => s.email)).toEqual(['ann@example.com'])
    expect((await client.post('/login/email/', { json: { email: 'not-an-email' }, ...json })).status).toBe(
      400,
    )

    const link = new URL(sent[0].url)
    expect(link.origin).toBe('http://testserver')
    const used = await client.get(link.pathname + link.search)
    expect(used.status).toBe(302)
    expect(used.headers.get('location')).toBe('/welcome/')
    expect((await me()).user.username).toBe('ann')
    const again = await createTestClient(app, { env }).get(link.pathname + link.search, json)
    expect(again.status).toBe(400)

    const strategy = strategies.get('email') as MagicLinkStrategy
    const user = (await User.objects.filter({ username: 'ann' }).first())!
    const token = await strategy.makeToken(user)
    const [pk, , sig] = token.split('.')
    const old = `${pk}.${(Math.floor(Date.now() / 1000) - 120).toString(36)}.${sig}`
    expect(await strategy.checkToken(old)).toBeNull()
    expect(await strategy.checkToken(token)).not.toBeNull()
    expect(await strategy.checkToken('garbage')).toBeNull()
  })

  it('bearer tokens as a REST authentication class', async () => {
    await User.objects.createUser('ann', 'ann@example.com', 'pw')
    const ok = await client.get('/api/me/', {
      headers: { authorization: 'Bearer k-ann', accept: 'application/json' },
    })
    expect(await ok.json()).toEqual({ username: 'ann' })
    const bad = await client.get('/api/me/', {
      headers: { authorization: 'Bearer nope', accept: 'application/json' },
    })
    expect(bad.status).toBe(401)
    expect(bad.headers.get('www-authenticate')).toBe('Bearer')
    const none = await client.get('/api/me/', { headers: { accept: 'application/json' } })
    expect([401, 403]).toContain(none.status)
  })
})
