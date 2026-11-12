// Minimal JWS verification and signing on WebCrypto (Workers and Node): ID tokens (JWKS), and JWTs we sign
// ourselves (Sign in with Apple client secrets, test providers).
import { b64url, fromB64url, fromUtf8, utf8 } from './crypto'
import { TokenValidationError } from './errors'
import { getJson } from './http'

export type JwsAlgorithm =
  | 'RS256'
  | 'RS384'
  | 'RS512'
  | 'PS256'
  | 'PS384'
  | 'PS512'
  | 'ES256'
  | 'ES384'
  | 'ES512'
  | 'EdDSA'

export const SUPPORTED_ALGORITHMS: readonly JwsAlgorithm[] = [
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'EdDSA',
]

type Jwk = JsonWebKey & { kid?: string; alg?: string; use?: string; crv?: string }

function params(alg: JwsAlgorithm): { importParams: any; verifyParams: any } {
  const hash = `SHA-${alg.slice(2)}`
  switch (alg.slice(0, 2)) {
    case 'RS':
      return {
        importParams: { name: 'RSASSA-PKCS1-v1_5', hash },
        verifyParams: { name: 'RSASSA-PKCS1-v1_5' },
      }
    case 'PS':
      return {
        importParams: { name: 'RSA-PSS', hash },
        verifyParams: { name: 'RSA-PSS', saltLength: Number(alg.slice(2)) / 8 },
      }
    case 'ES': {
      const namedCurve = { ES256: 'P-256', ES384: 'P-384', ES512: 'P-521' }[alg as 'ES256']
      return { importParams: { name: 'ECDSA', namedCurve }, verifyParams: { name: 'ECDSA', hash } }
    }
    default:
      return { importParams: { name: 'Ed25519' }, verifyParams: { name: 'Ed25519' } }
  }
}

export interface DecodedJwt {
  header: { alg: string; kid?: string; typ?: string; [k: string]: unknown }
  payload: Record<string, any>
  signingInput: string
  signature: Uint8Array<ArrayBuffer>
}

/** Split and decode without verifying. */
export function decodeJwt(token: string): DecodedJwt {
  const parts = token.split('.')
  if (parts.length !== 3) throw new TokenValidationError('Malformed JWT.')
  try {
    return {
      header: JSON.parse(fromUtf8(fromB64url(parts[0]))),
      payload: JSON.parse(fromUtf8(fromB64url(parts[1]))),
      signingInput: `${parts[0]}.${parts[1]}`,
      signature: fromB64url(parts[2]),
    }
  } catch {
    throw new TokenValidationError('Malformed JWT.')
  }
}

// ---- JWKS ----

const JWKS_TTL = 60 * 60 * 1000
const JWKS_MIN_REFRESH = 60 * 1000
const jwksCache = new Map<string, { keys: Jwk[]; fetchedAt: number }>()

async function fetchJwks(uri: string): Promise<Jwk[]> {
  const doc = await getJson(uri)
  const keys = Array.isArray(doc.keys) ? (doc.keys as Jwk[]) : []
  jwksCache.set(uri, { keys, fetchedAt: Date.now() })
  return keys
}

async function findKey(uri: string, kid: string | undefined, kty: string): Promise<Jwk | undefined> {
  const pick = (keys: Jwk[]) =>
    keys.find((k) => (kid === undefined || k.kid === kid) && k.kty === kty && (!k.use || k.use === 'sig'))
  const cached = jwksCache.get(uri)
  if (cached && Date.now() - cached.fetchedAt < JWKS_TTL) {
    const k = pick(cached.keys)
    if (k) return k
    // A rotated key: refetch, but not more than once a minute.
    if (Date.now() - cached.fetchedAt < JWKS_MIN_REFRESH) return undefined
  }
  return pick(await fetchJwks(uri))
}

/** Forget cached JWKS (tests, key rotation). */
export function clearJwksCache(): void {
  jwksCache.clear()
}

// ---- verify ----

export interface VerifyOptions {
  /** Where to fetch the signing keys. */
  jwksUri?: string
  /** Or the keys themselves. */
  keys?: Jwk[]
  /** Expected `iss`, or a predicate (multi-tenant issuers). */
  issuer?: string | ((iss: string) => boolean)
  /** Expected `aud` (the client id). */
  audience?: string
  nonce?: string
  /** Clock skew allowed, seconds (default 60). */
  leeway?: number
  algorithms?: readonly JwsAlgorithm[]
}

function ktyFor(alg: JwsAlgorithm): string {
  return alg.startsWith('ES') ? 'EC' : alg === 'EdDSA' ? 'OKP' : 'RSA'
}

/** Verify a JWS and its standard claims; returns the payload. Throws `TokenValidationError`. */
export async function verifyJwt(token: string, opts: VerifyOptions): Promise<Record<string, any>> {
  const { header, payload, signingInput, signature } = decodeJwt(token)
  const alg = header.alg as JwsAlgorithm
  if (!(opts.algorithms ?? SUPPORTED_ALGORITHMS).includes(alg)) {
    throw new TokenValidationError(`Unsupported or disallowed JWT algorithm '${header.alg}'.`)
  }
  const kty = ktyFor(alg)
  let jwk: Jwk | undefined
  if (opts.keys)
    jwk = opts.keys.find((k) => (header.kid === undefined || k.kid === header.kid) && k.kty === kty)
  else if (opts.jwksUri) jwk = await findKey(opts.jwksUri, header.kid, kty)
  if (!jwk) throw new TokenValidationError(`No signing key found for kid '${header.kid ?? ''}'.`)
  const { importParams, verifyParams } = params(alg)
  let ok: boolean
  try {
    const { alg: _a, use: _u, key_ops: _k, ...bare } = jwk as any
    const key = await crypto.subtle.importKey('jwk', bare, importParams, false, ['verify'])
    ok = await crypto.subtle.verify(verifyParams, key, signature, utf8(signingInput))
  } catch {
    ok = false
  }
  if (!ok) throw new TokenValidationError('Invalid JWT signature.')

  const now = Math.floor(Date.now() / 1000)
  const leeway = opts.leeway ?? 60
  if (opts.issuer !== undefined) {
    const iss = String(payload.iss ?? '')
    const good = typeof opts.issuer === 'function' ? opts.issuer(iss) : iss === opts.issuer
    if (!good) throw new TokenValidationError(`Unexpected issuer '${iss}'.`)
  }
  if (opts.audience !== undefined) {
    const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud]
    if (!aud.includes(opts.audience))
      throw new TokenValidationError('The token was issued for another client.')
    if (aud.length > 1 && payload.azp !== undefined && payload.azp !== opts.audience) {
      throw new TokenValidationError('The token was issued for another client (azp).')
    }
  }
  if (typeof payload.exp !== 'number' || payload.exp + leeway < now)
    throw new TokenValidationError('The token expired.')
  if (typeof payload.nbf === 'number' && payload.nbf - leeway > now)
    throw new TokenValidationError('The token is not valid yet.')
  if (typeof payload.iat === 'number' && payload.iat - leeway > now)
    throw new TokenValidationError('The token was issued in the future.')
  if (opts.nonce !== undefined && payload.nonce !== opts.nonce)
    throw new TokenValidationError('Nonce mismatch.')
  return payload
}

// ---- sign ----

/** Sign a JWT (ES256/RS256/EdDSA…). The key is a private JWK or a CryptoKey. */
export async function signJwt(
  payload: Record<string, unknown>,
  key: Jwk | CryptoKey,
  alg: JwsAlgorithm,
  header: Record<string, unknown> = {},
): Promise<string> {
  const { importParams, verifyParams } = params(alg)
  const cryptoKey =
    key instanceof CryptoKey
      ? key
      : await crypto.subtle.importKey(
          'jwk',
          (({ alg: _a, use: _u, key_ops: _k, ...bare }: any) => bare)(key),
          importParams,
          false,
          ['sign'],
        )
  const h = b64url(utf8(JSON.stringify({ alg, typ: 'JWT', ...header })))
  const p = b64url(utf8(JSON.stringify(payload)))
  const sig = await crypto.subtle.sign(verifyParams, cryptoKey, utf8(`${h}.${p}`))
  return `${h}.${p}.${b64url(sig)}`
}

/** Import a PKCS#8 PEM private key (e.g. Apple's `.p8`) for `signJwt`. */
export async function importPkcs8(pem: string, alg: JwsAlgorithm): Promise<CryptoKey> {
  const body = pem.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, '').replace(/\s+/g, '')
  const der = Uint8Array.from(atob(body), (ch) => ch.charCodeAt(0))
  return crypto.subtle.importKey('pkcs8', der, params(alg).importParams, false, ['sign'])
}
