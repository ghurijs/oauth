// A Worker running an OIDC login against a mock provider served from the same Worker (no network).
import { createApp, defineSettings, path } from '@ghuri/core'
import { authenticate, OIDCStrategy, strategies } from '../../src/index'
import { mockOAuthProvider } from '../../src/testing'

const ISSUER = 'https://idp.test'
const provider = mockOAuthProvider({
  issuer: ISSUER,
  profile: { sub: 'w-1', email: 'edge@example.com', email_verified: true },
})

strategies.use(
  'acme',
  new OIDCStrategy(
    { name: 'acme', issuer: ISSUER, clientId: 'edge-client', clientSecret: (env) => env.SECRET },
    async ({ profile }) => ({
      pk: profile.id,
      email: profile.email,
    }),
  ),
)

export default createApp(
  defineSettings((env) => ({
    SECRET_KEY: env.SECRET,
    INSTALLED_APPS: [],
    ROOT_URLCONF: [
      path(
        'login/acme/',
        authenticate('acme', {
          session: false,
          respond: (c, user) => c.json({ user, runtime: navigator.userAgent }),
        }),
      ),
      // the "user" approving at the provider
      path('__provider/approve/', async (c) => c.text(provider.authorize(c.req.query('url')!))),
    ],
  })),
  { checks: false },
)
