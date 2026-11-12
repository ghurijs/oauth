// OpenID Connect: discovery, nonce, ID token validation against the issuer's JWKS, userinfo.
import type { Context } from 'hono'
import { randomToken } from './crypto'
import { OAuthError, TokenValidationError } from './errors'
import { getJson } from './http'
import { type JwsAlgorithm, verifyJwt } from './jwt'
import {
  envValue,
  OAuth2Strategy,
  type OAuth2StrategyOptions,
  profileFromClaims,
  type VerifyFunction,
} from './oauth2'
import type { PendingFlow } from './state'
import type { EnvValue, OAuthTokens, Profile } from './types'

export interface DiscoveryDocument {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  userinfo_endpoint?: string
  jwks_uri: string
  revocation_endpoint?: string
  end_session_endpoint?: string
  id_token_signing_alg_values_supported?: string[]
  [k: string]: unknown
}

const DISCOVERY_TTL = 60 * 60 * 1000
const discoveryCache = new Map<string, { doc: DiscoveryDocument; fetchedAt: number }>()

/** Fetch (and cache for an hour) `<issuer>/.well-known/openid-configuration`. */
export async function discover(issuer: string): Promise<DiscoveryDocument> {
  const key = issuer.replace(/\/+$/, '')
  const hit = discoveryCache.get(key)
  if (hit && Date.now() - hit.fetchedAt < DISCOVERY_TTL) return hit.doc
  const doc = (await getJson(`${key}/.well-known/openid-configuration`)) as DiscoveryDocument
  for (const f of ['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as const) {
    if (typeof doc[f] !== 'string') throw new OAuthError(`The discovery document of ${key} has no ${f}.`)
  }
  discoveryCache.set(key, { doc, fetchedAt: Date.now() })
  return doc
}

export function clearDiscoveryCache(): void {
  discoveryCache.clear()
}

export interface OIDCStrategyOptions
  extends Omit<OAuth2StrategyOptions, 'authorizationURL' | 'tokenURL' | 'userInfoURL' | 'name'> {
  name?: string
  issuer: EnvValue<string>
  /** Skip discovery by giving the endpoints (any you leave out still come from discovery). */
  endpoints?: Partial<
    Pick<
      DiscoveryDocument,
      'authorization_endpoint' | 'token_endpoint' | 'userinfo_endpoint' | 'jwks_uri' | 'revocation_endpoint'
    >
  >
  /**
   * How to check the ID token's `iss`: exact match with the issuer (default), or a predicate for multi-tenant
   * issuers (Microsoft's `common` endpoint).
   */
  issuerValidation?: (iss: string) => boolean
  /** Also call the userinfo endpoint and merge its claims (default true when the issuer has one). */
  fetchUserInfo?: boolean
  algorithms?: readonly JwsAlgorithm[]
}

/** OpenID Connect login: OAuth2 + discovery + validated ID token. Default scope `openid email profile`. */
export class OIDCStrategy extends OAuth2Strategy {
  declare readonly options: OAuth2StrategyOptions & OIDCStrategyOptions

  constructor(options: OIDCStrategyOptions, verify: VerifyFunction) {
    const lazy = (pick: (d: DiscoveryDocument) => string | undefined, override?: string) => async () =>
      override ?? pick(await discover(await envValue(options.issuer))) ?? ''
    super(
      {
        ...options,
        name: options.name ?? 'oidc',
        scope: options.scope ?? ['openid', 'email', 'profile'],
        authorizationURL: lazy(
          (d) => d.authorization_endpoint,
          options.endpoints?.authorization_endpoint,
        ) as any,
        tokenURL: lazy((d) => d.token_endpoint, options.endpoints?.token_endpoint) as any,
        revocationURL: (options.revocationURL ??
          lazy((d) => d.revocation_endpoint, options.endpoints?.revocation_endpoint)) as any,
      },
      verify,
    )
  }

  async discovery(): Promise<DiscoveryDocument> {
    const e = this.options.endpoints
    const issuer = await envValue(this.options.issuer)
    if (e?.authorization_endpoint && e.token_endpoint && e.jwks_uri) {
      return { issuer, ...e } as DiscoveryDocument
    }
    return { ...(await discover(issuer)), ...(e ?? {}) }
  }

  protected override async startExtras(_c: Context) {
    return { nonce: randomToken(16) }
  }

  /** Validate an ID token from this provider (also used for tokens obtained by native SDKs). */
  async validateIdToken(idToken: string, nonce?: string): Promise<Record<string, any>> {
    const doc = await this.discovery()
    const issuer = await envValue(this.options.issuer)
    return verifyJwt(idToken, {
      jwksUri: doc.jwks_uri,
      issuer: this.options.issuerValidation ?? doc.issuer ?? issuer,
      audience: await envValue(this.options.clientId),
      nonce,
      algorithms: this.options.algorithms,
    })
  }

  override async userProfile(tokens: OAuthTokens, c: Context, flow?: PendingFlow): Promise<Profile> {
    if (!tokens.idToken) throw new OAuthError('The provider did not return an ID token.', 'missing_id_token')
    let claims: Record<string, any>
    try {
      claims = await this.validateIdToken(tokens.idToken, flow?.nonce)
    } catch (err) {
      if (err instanceof TokenValidationError)
        throw new OAuthError(`Invalid ID token: ${err.message}`, 'invalid_id_token')
      throw err
    }
    const doc = await this.discovery()
    if (this.options.fetchUserInfo !== false && doc.userinfo_endpoint) {
      const info = await this.profileContext(c, tokens).getJsonAuthed(doc.userinfo_endpoint)
      if (info.sub !== undefined && String(info.sub) !== String(claims.sub)) {
        throw new OAuthError('The userinfo subject does not match the ID token.', 'invalid_userinfo')
      }
      claims = { ...info, ...claims }
    }
    if (this.options.profile)
      return this.options.profile(
        { ...tokens, raw: { ...tokens.raw, claims } },
        this.profileContext(c, tokens),
      )
    return profileFromClaims(this.name, claims)
  }
}
