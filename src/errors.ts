import { GhuriError } from '@ghuri/core'

export class OAuthError extends GhuriError {
  constructor(
    message: string,
    /** The provider's `error` code, when there is one. */
    readonly code?: string,
    readonly details?: unknown,
  ) {
    super(message)
  }
}

/** An ID token failed validation (signature, issuer, audience, expiry or nonce). */
export class TokenValidationError extends OAuthError {}
