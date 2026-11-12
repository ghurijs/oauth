// Round-trip state for redirect flows (state, PKCE verifier, nonce, next) in an encrypted, short-lived cookie,
// so OAuth works without sessions. Several pending flows can coexist (two tabs).
import { isSecure, tryGetContext } from '@ghuri/core'
import type { Context } from 'hono'
import { deleteCookie, getCookie, setCookie } from 'hono/cookie'
import { seal, unseal } from './crypto'

export interface PendingFlow {
  state: string
  strategy: string
  redirectUri: string
  verifier?: string
  nonce?: string
  next?: string
  extra?: Record<string, string>
  /** ms since epoch */
  createdAt: number
}

const PURPOSE = 'oauth-state'
const MAX_FLOWS = 5

export function stateSettings(): { cookie: string; maxAge: number } {
  const s = (tryGetContext()?.settings.OAUTH ?? {}) as { STATE_COOKIE?: string; STATE_MAX_AGE?: number }
  return { cookie: s.STATE_COOKIE ?? 'ghuri_oauth', maxAge: s.STATE_MAX_AGE ?? 600 }
}

async function read(c: Context): Promise<PendingFlow[]> {
  const { cookie, maxAge } = stateSettings()
  const raw = getCookie(c, cookie)
  if (!raw) return []
  const json = await unseal(raw, PURPOSE)
  if (!json) return []
  try {
    const flows = JSON.parse(json) as PendingFlow[]
    const now = Date.now()
    return Array.isArray(flows) ? flows.filter((f) => f && now - f.createdAt <= maxAge * 1000) : []
  } catch {
    return []
  }
}

async function write(c: Context, flows: PendingFlow[]): Promise<void> {
  const { cookie, maxAge } = stateSettings()
  if (!flows.length) {
    deleteCookie(c, cookie, { path: '/', secure: isSecure(c) })
    return
  }
  setCookie(c, cookie, await seal(JSON.stringify(flows), PURPOSE), {
    path: '/',
    httpOnly: true,
    secure: isSecure(c),
    // Lax: the provider's redirect back is a top-level GET navigation, which Lax cookies accompany.
    sameSite: 'Lax',
    maxAge,
  })
}

/** Remember a flow until the callback (newest five kept). */
export async function savePending(c: Context, flow: PendingFlow): Promise<void> {
  const flows = (await read(c)).filter((f) => f.state !== flow.state)
  flows.push(flow)
  await write(c, flows.slice(-MAX_FLOWS))
}

/** Take the flow for `state` (single use). Null when it is unknown or expired. */
export async function takePending(c: Context, state: string | undefined): Promise<PendingFlow | null> {
  if (!state) return null
  const flows = await read(c)
  const flow = flows.find((f) => f.state === state) ?? null
  if (flow)
    await write(
      c,
      flows.filter((f) => f !== flow),
    )
  return flow
}
