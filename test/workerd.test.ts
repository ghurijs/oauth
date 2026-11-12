// The OIDC flow in workerd: WebCrypto ES256 signing/verification, HKDF + AES-GCM state cookie, PKCE.
import { fileURLToPath } from 'node:url'
import { build } from 'esbuild'
import { Miniflare } from 'miniflare'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

describe('OIDC login on workerd', () => {
  let mf: Miniflare
  beforeAll(async () => {
    const out = await build({
      entryPoints: [fileURLToPath(new URL('./fixtures/worker.ts', import.meta.url))],
      bundle: true,
      format: 'esm',
      platform: 'neutral',
      target: 'es2022',
      mainFields: ['module', 'main'],
      conditions: ['workerd', 'worker', 'browser', 'import'],
      external: ['node:*', 'cloudflare:*', 'postgres'],
      write: false,
      logLevel: 'silent',
    })
    mf = new Miniflare({
      modules: true,
      script: out.outputFiles[0].text,
      compatibilityDate: '2025-06-01',
      compatibilityFlags: ['nodejs_compat'],
      bindings: { SECRET: 'edge-secret' },
    })
  }, 60_000)
  afterAll(async () => {
    await mf?.dispose()
  })

  it('redirects, validates the ID token and answers with the user', async () => {
    const start = await mf.dispatchFetch('https://example.com/login/acme/', { redirect: 'manual' })
    expect(start.status).toBe(302)
    const cookie = start.headers.get('set-cookie')!.split(';')[0]
    expect(cookie).toMatch(/^ghuri_oauth=/)
    const approve = await mf.dispatchFetch(
      `https://example.com/__provider/approve/?url=${encodeURIComponent(start.headers.get('location')!)}`,
    )
    const callback = await approve.text()
    expect(callback.startsWith('https://example.com/login/acme/?')).toBe(true)
    const done = await mf.dispatchFetch(callback, { headers: { cookie }, redirect: 'manual' })
    expect(await done.json()).toEqual({
      user: { pk: 'w-1', email: 'edge@example.com' },
      runtime: 'Cloudflare-Workers',
    })
    const replay = await mf.dispatchFetch(callback, {
      redirect: 'manual',
      headers: { accept: 'application/json' },
    })
    expect(replay.status).toBe(400)
  })
})
