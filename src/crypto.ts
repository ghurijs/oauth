// WebCrypto helpers (Workers and Node): random values, PKCE, base64url, AES-GCM with a key from SECRET_KEY.
import { ImproperlyConfigured, tryGetContext } from '@ghuri/core'

const enc = new TextEncoder()
const dec = new TextDecoder()

export function b64url(bytes: Uint8Array | ArrayBuffer): string {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let s = ''
  for (const b of u) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function fromB64url(value: string): Uint8Array<ArrayBuffer> {
  const s = value.replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4))
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

export function utf8(value: string): Uint8Array<ArrayBuffer> {
  return enc.encode(value) as Uint8Array<ArrayBuffer>
}

export function fromUtf8(bytes: Uint8Array): string {
  return dec.decode(bytes)
}

/** URL-safe random string with `bytes` bytes of entropy. */
export function randomToken(bytes = 32): string {
  return b64url(crypto.getRandomValues(new Uint8Array(bytes)))
}

export async function sha256(value: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(value)))
}

/** PKCE: a verifier and its S256 challenge. */
export async function pkcePair(): Promise<{ verifier: string; challenge: string }> {
  const verifier = randomToken(32)
  return { verifier, challenge: b64url(await sha256(verifier)) }
}

export function secretKey(): string {
  const key = tryGetContext()?.settings.SECRET_KEY as string | undefined
  if (!key) throw new ImproperlyConfigured('The SECRET_KEY setting must not be empty.')
  return key
}

function fallbackKeys(): string[] {
  return (tryGetContext()?.settings.SECRET_KEY_FALLBACKS as string[] | undefined) ?? []
}

const keyCache = new Map<string, Promise<CryptoKey>>()

async function aesKey(secret: string, purpose: string): Promise<CryptoKey> {
  const id = `${purpose}\u0000${secret}`
  let k = keyCache.get(id)
  if (!k) {
    k = (async () => {
      const base = await crypto.subtle.importKey('raw', utf8(secret), 'HKDF', false, ['deriveKey'])
      return crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: utf8('ghuri.oauth'), info: utf8(purpose) },
        base,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt'],
      )
    })()
    if (keyCache.size > 32) keyCache.clear()
    keyCache.set(id, k)
  }
  return k
}

/** Encrypt and authenticate a string with a key derived from `SECRET_KEY` for `purpose`. */
export async function seal(plaintext: string, purpose: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const key = await aesKey(secretKey(), purpose)
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, utf8(plaintext)))
  const out = new Uint8Array(iv.length + ct.length)
  out.set(iv)
  out.set(ct, iv.length)
  return b64url(out)
}

/** Decrypt what `seal()` produced (also with `SECRET_KEY_FALLBACKS`). Null when it fails. */
export async function unseal(sealed: string, purpose: string): Promise<string | null> {
  let data: Uint8Array<ArrayBuffer>
  try {
    data = fromB64url(sealed)
  } catch {
    return null
  }
  if (data.length < 13) return null
  const iv = data.slice(0, 12)
  const ct = data.slice(12)
  for (const secret of [secretKey(), ...fallbackKeys()]) {
    try {
      const key = await aesKey(secret, purpose)
      return fromUtf8(new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct)))
    } catch {
      // try the next key
    }
  }
  return null
}

export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let r = 0
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return r === 0
}
