export {
  authenticate,
  completeLogin,
  failureResponse,
  loginBackendName,
  type NamedResult,
  runStrategy,
  userInfo,
} from './authenticate'
export { OAuth2Client, type OAuth2ClientConfig, toTokens } from './client'
export { b64url, fromB64url, pkcePair, randomToken, seal, unseal, utf8 } from './crypto'
export { OAuthError, TokenValidationError } from './errors'
export { getJson, providerFetch, readBody, setProviderFetch } from './http'
export {
  clearJwksCache,
  type DecodedJwt,
  decodeJwt,
  importPkcs8,
  type JwsAlgorithm,
  SUPPORTED_ALGORITHMS,
  signJwt,
  type VerifyOptions,
  verifyJwt,
} from './jwt'
export {
  BearerStrategy,
  type BearerVerify,
  LocalStrategy,
  type LocalStrategyOptions,
  type LocalVerify,
  type MagicLinkOptions,
  MagicLinkStrategy,
  type MagicLinkVerify,
} from './local'
export {
  envValue,
  OAuth2Strategy,
  type OAuth2StrategyOptions,
  type ProfileContext,
  profileFromClaims,
  type VerifyFunction,
  type VerifyParams,
  type VerifyResult,
} from './oauth2'
export {
  clearDiscoveryCache,
  type DiscoveryDocument,
  discover,
  OIDCStrategy,
  type OIDCStrategyOptions,
} from './oidc'
export { type PendingFlow, savePending, stateSettings, takePending } from './state'
export { CustomStrategy, resolveStrategy, Strategy, type StrategyRef, strategies } from './strategy'
export type {
  AuthenticateOptions,
  EnvValue,
  OAuthTokens,
  Profile,
  StrategyResult,
  StrategyUser,
} from './types'
