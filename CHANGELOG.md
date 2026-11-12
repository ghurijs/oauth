# Changelog

## Unreleased

- Export `sha256` and `timingSafeEqual` from the main entry (used by `@ghuri/oauth-provider`).

## 0.1.0-alpha.0

- Initial alpha (ARCHITECTURE.md §17).
- Strategies and registry (`Strategy`, `strategies.use()`), `authenticate()` views and `runStrategy()`; success
  responses as a session login, a JWT pair or your own response.
- `OAuth2Strategy` (authorization code + PKCE), `OIDCStrategy` (discovery, nonce, ID token validation with JWKS on
  WebCrypto), `LocalStrategy`, `MagicLinkStrategy`, `BearerStrategy`, `CustomStrategy`.
- Encrypted round-trip state cookie (several pending flows), `OAuth2Client`, `verifyJwt` / `signJwt` / `importPkcs8`.
- `@ghuri/oauth/rest`: `StrategyAuthentication`. `@ghuri/oauth/testing`: `mockOAuthProvider`, `followOAuth`.
