# @ghuri/oauth

Login building blocks for [Ghuri](https://github.com/ghurijs/ghuri), in the style of **Passport.js**: register
**strategies** and turn them into views with `authenticate()`. OAuth 2.0 (PKCE), OpenID Connect (discovery, ID token
validation), username/password, magic links and bearer tokens are built in; write your own for anything else. Runs on
Cloudflare Workers and Node with WebCrypto only.

For "Log in with GitHub / Google" without writing code, use [`@ghuri/socialauth`](https://github.com/ghurijs/socialauth),
which is built on this package.

> Status: alpha (ARCHITECTURE.md §17). Needs `@ghuri/core` and `@ghuri/auth` 0.1.0-alpha.1 or later.

```sh
npm install @ghuri/oauth
```

## Quick start

```ts
// src/accounts/strategies.ts
import { MagicLinkStrategy, OIDCStrategy, strategies } from '@ghuri/oauth'
import { User } from '@ghuri/auth'

strategies.use(
  'acme',
  new OIDCStrategy(
    {
      name: 'acme',
      issuer: 'https://login.acme.example',
      clientId: (env) => env.ACME_CLIENT_ID,
      clientSecret: (env) => env.ACME_CLIENT_SECRET,
    },
    // verify: the provider's profile → your user (null refuses the login)
    async ({ profile }) =>
      (await User.objects.filter({ email: profile.email }).first()) ??
      User.objects.createUser(profile.username ?? profile.id, profile.email),
  ),
)

strategies.use(
  'email',
  new MagicLinkStrategy(
    { send: async ({ email, url }) => sendMail(email, 'Your login link', url) },
    async ({ email }) => User.objects.filter({ email }).first(),
  ),
)
```

```ts
// src/accounts/urls.ts
import { path } from '@ghuri/core'
import { authenticate } from '@ghuri/oauth'
import './strategies'

export const urlpatterns = [
  // one URL for both legs: without ?code it redirects to the provider, with it it logs in
  path('login/acme/', authenticate('acme', { failureRedirect: '/login/' })),
  path('login/email/', authenticate('email', { successRedirect: '/' })),
]
```

## Strategies

A strategy's `authenticate(c, options)` returns one of:

| Result | Meaning |
|---|---|
| `{ type: 'success', user, info? }` | Log this user in. |
| `{ type: 'fail', status?, message?, challenge? }` | Refuse (`challenge` becomes `WWW-Authenticate`). |
| `{ type: 'redirect', url }` | Send the browser somewhere (the provider). |
| `{ type: 'pass' }` | Not for me: try the next strategy. |
| `{ type: 'error', error }` | Something broke (becomes a 500). |
| `{ type: 'response', response }` | The strategy answered itself ("we sent you a link"). |

| Built-in | |
|---|---|
| `OAuth2Strategy` | Authorization code flow with PKCE (S256) and state. `authorizationURL`, `tokenURL`, `clientId`, `clientSecret`, `scope`, `userInfoURL` or `profile(tokens, ctx)`, `tokenAuth: 'body' \| 'basic'`, `authorizationParams`, `callbackURL`. |
| `OIDCStrategy` | OAuth2 + discovery (`issuer`), `nonce`, ID token validation against the issuer's JWKS (RS*, PS*, ES*, EdDSA; `iss`, `aud`/`azp`, `exp`, `nbf`, `iat`, `nonce`), userinfo. `issuerValidation` for multi-tenant issuers. |
| `LocalStrategy` | Username/password from a JSON or form POST. Default `verify` is `@ghuri/auth`'s `authenticate()`. |
| `MagicLinkStrategy` | `POST { email }` sends a link (same answer for unknown addresses); `GET ?token=` logs in. Links expire (`maxAge`, default 15 minutes) and stop working after one login. |
| `BearerStrategy` | `Authorization: Bearer <token>` → `verify(token)`. For API keys. |
| `CustomStrategy` | `new CustomStrategy('name', (c, options) => result)`. |

Settings values can be functions of the env: `clientId: (env) => env.ACME_CLIENT_ID`.

Profiles are normalized: `{ provider, id, email?, emailVerified?, username?, name?, firstName?, lastName?, avatarUrl?, raw }`.

## `authenticate(names, options)`

Turns strategies into a view. Several names are tried in order until one does not pass.

| Option | |
|---|---|
| `successRedirect` / `failureRedirect` | Where to go (failures add `?error=<message>`). |
| `successReturnToOrRedirect` | The safe `next` kept across the round trip, else this. |
| `respond` | `'session'` (default: `@ghuri/auth` `login()`), `'jwt'` (JSON `{ access, refresh, user }`), or `(c, user, info) => Response`. |
| `session` | `false` to skip the session login. |
| `next` | Override the `next` URL (default: the `?next=` query parameter). |
| `scope`, `state` | Extra scopes; extra values kept across the round trip (`info.state`). |

Without redirects configured, JSON clients get `{ user }` (or `{ detail }` with 401) and browsers go to a safe `next`
or `LOGIN_REDIRECT_URL`. `runStrategy(c, names)` runs strategies inside your own view.

## Round-trip state

`state`, the PKCE verifier, the OIDC `nonce` and `next` live in an encrypted (AES-GCM, key derived from `SECRET_KEY`
with HKDF), HttpOnly, `SameSite=Lax`, 10-minute cookie, so flows work without sessions. Up to five pending flows
coexist (several tabs). A missing, expired or reused state fails with 400; the provider's `error=access_denied`
fails with "You cancelled the login."

## REST

```ts
import { StrategyAuthentication } from '@ghuri/oauth/rest'

strategies.use('api-key', new BearerStrategy(async (token) => ApiKey.userFor(token)))

class Reports extends APIView {
  authenticationClasses = [StrategyAuthentication(['api-key'])]
}
```

## Lower-level pieces

`OAuth2Client` (`authorizationUrl`, `exchangeCode`, `refresh`, `revoke`), `discover(issuer)`, `verifyJwt(token, opts)`,
`signJwt(payload, key, alg)`, `importPkcs8(pem, alg)`, `seal` / `unseal`, `pkcePair()`.

## Settings

```ts
OAUTH: {
  STATE_COOKIE: 'ghuri_oauth',
  STATE_MAX_AGE: 600,
  HTTP_TIMEOUT: 10_000,
  CALLBACK_BASE_URL: undefined,   // default: the request's origin; set it behind proxies that rewrite the host
}
```

## Testing

```ts
import { followOAuth, mockOAuthProvider } from '@ghuri/oauth/testing'

const provider = mockOAuthProvider({ issuer: 'https://login.acme.example', profile: { sub: '42', email: 'ann@example.com', email_verified: true } })
const res = await followOAuth(client, '/login/acme/', provider)   // redirect → approve → callback
provider.restore()
```

The mock intercepts provider requests (token, userinfo, discovery, JWKS, plus `routes` you add), checks PKCE and the
redirect URI, and signs ID tokens with a fresh ES256 key.
