// ID token validation, signing round trips and sealed state.
import { createContext, runWithContext } from '@ghuri/core'
import { describe, expect, it } from 'vitest'
import { b64url, decodeJwt, seal, signJwt, TokenValidationError, unseal, utf8, verifyJwt } from '../src/index'

async function keyPair(alg: 'ES256' | 'RS256' | 'EdDSA') {
  const params =
    alg === 'ES256'
      ? { name: 'ECDSA', namedCurve: 'P-256' }
      : alg === 'RS256'
        ? {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
          }
        : { name: 'Ed25519' }
  const pair = (await crypto.subtle.generateKey(params as any, true, ['sign', 'verify'])) as CryptoKeyPair
  const jwk = { ...(await crypto.subtle.exportKey('jwk', pair.publicKey)), kid: `${alg}-k` }
  return { privateKey: pair.privateKey, jwk }
}

const now = () => Math.floor(Date.now() / 1000)
const claims = (extra: Record<string, unknown> = {}) => ({
  iss: 'https://idp.test',
  aud: 'client-1',
  sub: '42',
  iat: now(),
  exp: now() + 300,
  nonce: 'n-1',
  ...extra,
})
const opts = (jwk: any, extra: Record<string, unknown> = {}) => ({
  keys: [jwk],
  issuer: 'https://idp.test',
  audience: 'client-1',
  nonce: 'n-1',
  ...extra,
})

describe('verifyJwt', () => {
  it.each(['ES256', 'RS256', 'EdDSA'] as const)('accepts valid %s tokens', async (alg) => {
    const { privateKey, jwk } = await keyPair(alg)
    const token = await signJwt(claims(), privateKey, alg, { kid: jwk.kid })
    expect((await verifyJwt(token, opts(jwk))).sub).toBe('42')
  })

  it('rejects bad signatures, alg none, and wrong claims', async () => {
    const { privateKey, jwk } = await keyPair('ES256')
    const other = await keyPair('ES256')
    const sign = (c: Record<string, unknown>) => signJwt(claims(c), privateKey, 'ES256', { kid: jwk.kid })
    const fails = async (token: string, o = opts(jwk), msg?: RegExp) => {
      const p = verifyJwt(token, o)
      await expect(p).rejects.toBeInstanceOf(TokenValidationError)
      if (msg) await expect(p).rejects.toThrow(msg)
    }
    await fails(await signJwt(claims(), other.privateKey, 'ES256', { kid: jwk.kid }), opts(jwk), /signature/)
    const parts = (await sign({})).split('.')
    await fails(`${b64url(utf8(JSON.stringify({ alg: 'none' })))}.${parts[1]}.`, opts(jwk), /algorithm/)
    await fails(
      `${parts[0]}.${b64url(utf8(JSON.stringify(claims({ sub: 'admin' }))))}.${parts[2]}`,
      opts(jwk),
      /signature/,
    )
    await fails(await sign({ aud: 'someone-else' }), opts(jwk), /another client/)
    await fails(await sign({ aud: ['client-1', 'x'], azp: 'x' }), opts(jwk), /azp/)
    await fails(await sign({ iss: 'https://evil.test' }), opts(jwk), /issuer/)
    await fails(await sign({ exp: now() - 120 }), opts(jwk), /expired/)
    await fails(await sign({ nonce: 'other' }), opts(jwk), /Nonce/)
    await fails(await sign({ nbf: now() + 600 }), opts(jwk), /not valid yet/)
    await fails('not.a.jwt.at-all', opts(jwk), /Malformed/)
    await fails(await sign({}), opts({ ...jwk, kid: 'rotated' }), /No signing key/)
    expect(await verifyJwt(await sign({ exp: now() - 30 }), opts(jwk))).toBeTruthy() // within leeway
    expect(
      await verifyJwt(
        await sign({ iss: 'https://login.example/t-9/v2.0' }),
        opts(jwk, { issuer: (i: string) => i.startsWith('https://login.example/') }),
      ),
    ).toBeTruthy()
  })

  it('decodes without verifying', async () => {
    const { privateKey, jwk } = await keyPair('ES256')
    const d = decodeJwt(await signJwt(claims(), privateKey, 'ES256', { kid: jwk.kid }))
    expect(d.header).toMatchObject({ alg: 'ES256', kid: jwk.kid, typ: 'JWT' })
  })
})

describe('sealed state', () => {
  const run = <T>(settings: Record<string, unknown>, fn: () => Promise<T>) =>
    runWithContext(createContext({ env: {}, settings: settings as any }), fn)

  it('round-trips, detects tampering and honors key fallbacks', async () => {
    const sealed = await run({ SECRET_KEY: 'k1' }, () => seal('{"a":1}', 'p'))
    expect(await run({ SECRET_KEY: 'k1' }, () => unseal(sealed, 'p'))).toBe('{"a":1}')
    expect(await run({ SECRET_KEY: 'k1' }, () => unseal(sealed, 'other-purpose'))).toBeNull()
    expect(await run({ SECRET_KEY: 'k2' }, () => unseal(sealed, 'p'))).toBeNull()
    expect(await run({ SECRET_KEY: 'k2', SECRET_KEY_FALLBACKS: ['k1'] }, () => unseal(sealed, 'p'))).toBe(
      '{"a":1}',
    )
    const flipped = sealed.slice(0, -2) + (sealed.endsWith('A') ? 'BB' : 'AA')
    expect(await run({ SECRET_KEY: 'k1' }, () => unseal(flipped, 'p'))).toBeNull()
    expect(await run({ SECRET_KEY: 'k1' }, () => unseal('%%%', 'p'))).toBeNull()
  })
})
