// Outgoing requests to identity providers: timeouts, JSON/form parsing, and a test hook to stub `fetch`.
import { tryGetContext } from '@ghuri/core'
import { OAuthError } from './errors'

type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>

const KEY = Symbol.for('ghuri.oauth.fetch')

/** Replace the fetch used for provider requests (tests). Pass undefined to restore `globalThis.fetch`. */
export function setProviderFetch(fn: FetchLike | undefined): void {
  ;(globalThis as any)[KEY] = fn
}

export function providerFetch(input: string | URL | Request, init: RequestInit = {}): Promise<Response> {
  const fn = ((globalThis as any)[KEY] as FetchLike | undefined) ?? fetch
  const timeout = ((tryGetContext()?.settings.OAUTH as any)?.HTTP_TIMEOUT as number | undefined) ?? 10_000
  const headers = new Headers(init.headers)
  if (!headers.has('user-agent')) headers.set('user-agent', 'ghuri-oauth')
  return fn(input, { ...init, headers, signal: init.signal ?? AbortSignal.timeout(timeout) })
}

/** Parse a provider response as JSON or `application/x-www-form-urlencoded` (GitHub's legacy token format). */
export async function readBody(res: Response): Promise<Record<string, unknown>> {
  const text = await res.text()
  const type = res.headers.get('content-type') ?? ''
  if (
    type.includes('application/x-www-form-urlencoded') ||
    (!type.includes('json') && text.includes('=') && !text.trim().startsWith('{'))
  ) {
    return Object.fromEntries(new URLSearchParams(text))
  }
  try {
    return text ? (JSON.parse(text) as Record<string, unknown>) : {}
  } catch {
    throw new OAuthError(
      `Provider answered ${res.status} with a body that is not JSON.`,
      'invalid_response',
      text.slice(0, 200),
    )
  }
}

/** GET a JSON document (userinfo, discovery, JWKS); throws `OAuthError` on HTTP errors. */
export async function getJson(url: string, init: RequestInit = {}): Promise<Record<string, any>> {
  const headers = new Headers(init.headers)
  if (!headers.has('accept')) headers.set('accept', 'application/json')
  const res = await providerFetch(url, { ...init, headers })
  const body = await readBody(res)
  if (!res.ok) {
    throw new OAuthError(
      `GET ${new URL(url).origin}${new URL(url).pathname} failed with ${res.status}.`,
      (body.error as string | undefined) ?? 'http_error',
      body,
    )
  }
  return body
}
