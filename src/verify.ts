import jwt from 'jsonwebtoken'
import { TokenPayloadSchema, type TokenPayload } from './schema.js'

/**
 * Optional hook to reject an otherwise-valid, unexpired token — e.g. because
 * the user's session or the token's `jti` was revoked. Return `true` to
 * reject (revoked), `false`/`undefined` to allow. May be async (DB/cache
 * lookup).
 */
export type RevocationCheck = (
  payload: TokenPayload,
  token: string,
) => boolean | Promise<boolean>

export interface VerifyAccessTokenOptions {
  /** HS256 signing secret. Must match the value bamware-auth-service signs with. */
  secret: string
  revocationCheck?: RevocationCheck
}

export class TokenVerificationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'TokenVerificationError'
  }
}

/**
 * Verify a Bamware access token's signature, expiry, and payload shape.
 *
 * Throws `TokenVerificationError` when the token is missing, malformed,
 * expired, signed with a different secret, has a payload that doesn't match
 * `TokenPayloadSchema`, or is rejected by `revocationCheck`.
 */
export async function verifyAccessToken(
  token: string,
  options: VerifyAccessTokenOptions,
): Promise<TokenPayload> {
  let decoded: unknown
  try {
    decoded = jwt.verify(token, options.secret)
  } catch {
    // Covers TokenExpiredError, JsonWebTokenError (bad signature/malformed),
    // NotBeforeError.
    throw new TokenVerificationError('Invalid or expired token')
  }

  const result = TokenPayloadSchema.safeParse(decoded)
  if (!result.success) {
    throw new TokenVerificationError('Invalid token payload')
  }

  if (options.revocationCheck) {
    const revoked = await options.revocationCheck(result.data, token)
    if (revoked) {
      throw new TokenVerificationError('Token has been revoked')
    }
  }

  return result.data
}
