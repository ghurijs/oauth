// An OAuth 2.0 client (RFC 6749 + PKCE, RFC 7636): authorization URLs, code exchange, refresh, revoke.
import { OAuthError } from './errors'
import { providerFetch, readBody } from './http'
import type { OAuthTokens } from './types'

export interface OAuth2ClientConfig {
  authorizationURL: string
  tokenURL: string
  clientId: string
  clientSecret?: string
  /** How to send client credentials to the token endpoint (default `'body'`). */
  tokenAuth?: 'body' | 'basic'
  revocationURL?: string
  scopeSeparator?: string
}

export function toTokens(body: Record<string, unknown>): OAuthTokens {
  const accessToken = body.access_token
  if (typeof accessToken !== 'string' || !accessToken) {
    throw new OAuthError(
      String(body.error_description ?? body.error ?? 'The provider did not return an access token.'),
      typeof body.error === 'string' ? body.error : 'invalid_token_response',
      body,
    )
  }
  const expiresIn = body.expires_in === undefined ? undefined : Number(body.expires_in)
  return {
    accessToken,
    tokenType: typeof body.token_type === 'string' ? body.token_type : undefined,
    refreshToken: typeof body.refresh_token === 'string' ? body.refresh_token : undefined,
    expiresIn: Number.isFinite(expiresIn) ? expiresIn : undefined,
    expiresAt: Number.isFinite(expiresIn) ? Date.now() + (expiresIn as number) * 1000 : undefined,
    idToken: typeof body.id_token === 'string' ? body.id_token : undefined,
    scope: typeof body.scope === 'string' ? body.scope : undefined,
    raw: body,
  }
}

export class OAuth2Client {
  constructor(readonly config: OAuth2ClientConfig) {}

  authorizationUrl(opts: {
    redirectUri: string
    state: string
    scope?: string[]
    codeChallenge?: string
    nonce?: string
    params?: Record<string, string>
  }): string {
    const url = new URL(this.config.authorizationURL)
    const q = url.searchParams
    q.set('response_type', 'code')
    q.set('client_id', this.config.clientId)
    q.set('redirect_uri', opts.redirectUri)
    q.set('state', opts.state)
    if (opts.scope?.length) q.set('scope', opts.scope.join(this.config.scopeSeparator ?? ' '))
    if (opts.codeChallenge) {
      q.set('code_challenge', opts.codeChallenge)
      q.set('code_challenge_method', 'S256')
    }
    if (opts.nonce) q.set('nonce', opts.nonce)
    for (const [k, v] of Object.entries(opts.params ?? {})) q.set(k, v)
    return url.toString()
  }

  private async tokenRequest(form: Record<string, string>): Promise<OAuthTokens> {
    const body = new URLSearchParams(form)
    const headers: Record<string, string> = {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    }
    if (this.config.tokenAuth === 'basic' && this.config.clientSecret !== undefined) {
      const id = encodeURIComponent(this.config.clientId)
      const secret = encodeURIComponent(this.config.clientSecret)
      headers.authorization = `Basic ${btoa(`${id}:${secret}`)}`
    } else {
      body.set('client_id', this.config.clientId)
      if (this.config.clientSecret !== undefined) body.set('client_secret', this.config.clientSecret)
    }
    const res = await providerFetch(this.config.tokenURL, { method: 'POST', headers, body })
    const data = await readBody(res)
    if (!res.ok && !data.error) {
      throw new OAuthError(`The token endpoint answered ${res.status}.`, 'http_error', data)
    }
    return toTokens(data)
  }

  exchangeCode(code: string, redirectUri: string, codeVerifier?: string): Promise<OAuthTokens> {
    const form: Record<string, string> = { grant_type: 'authorization_code', code, redirect_uri: redirectUri }
    if (codeVerifier) form.code_verifier = codeVerifier
    return this.tokenRequest(form)
  }

  refresh(refreshToken: string, scope?: string[]): Promise<OAuthTokens> {
    const form: Record<string, string> = { grant_type: 'refresh_token', refresh_token: refreshToken }
    if (scope?.length) form.scope = scope.join(this.config.scopeSeparator ?? ' ')
    return this.tokenRequest(form)
  }

  /** RFC 7009 token revocation (needs `revocationURL`). */
  async revoke(token: string, hint?: 'access_token' | 'refresh_token'): Promise<void> {
    if (!this.config.revocationURL) throw new OAuthError('This provider has no revocation endpoint.')
    const body = new URLSearchParams({ token, client_id: this.config.clientId })
    if (hint) body.set('token_type_hint', hint)
    if (this.config.clientSecret !== undefined) body.set('client_secret', this.config.clientSecret)
    const res = await providerFetch(this.config.revocationURL, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    })
    if (!res.ok) throw new OAuthError(`Token revocation failed with ${res.status}.`, 'revocation_failed')
  }
}
