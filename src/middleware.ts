import type { NextFunction, Request, Response } from 'express'
import { verifyAccessToken, type RevocationCheck } from './verify.js'
import type { TokenPayload } from './schema.js'

export interface AuthenticatedRequest extends Request {
  caller: TokenPayload
}

export interface AuthenticateOptions {
  /** HS256 signing secret. Must match the value bamware-auth-service signs with. */
  secret: string
  /** Reject (403) any token whose `tenantId` doesn't match this value. */
  tenantId: string
  revocationCheck?: RevocationCheck
}

/**
 * Express middleware: verifies the `Authorization: Bearer <token>` header
 * against `TokenPayloadSchema`, then enforces tenant scoping.
 *
 * - 401 — missing/malformed header, invalid signature, expired, revoked.
 * - 403 — valid token, but `payload.tenantId !== options.tenantId`.
 *
 * On success, sets `req.caller` to the verified `TokenPayload` and calls
 * `next()`.
 */
export function authenticate(options: AuthenticateOptions) {
  return async function authenticateMiddleware(
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> {
    const auth = req.headers.authorization
    if (!auth?.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Missing or invalid authorization header' })
      return
    }

    const token = auth.slice(7)

    let payload: TokenPayload
    try {
      payload = await verifyAccessToken(token, {
        secret: options.secret,
        revocationCheck: options.revocationCheck,
      })
    } catch {
      res.status(401).json({ error: 'Invalid or expired token' })
      return
    }

    if (payload.tenantId !== options.tenantId) {
      res.status(403).json({ error: 'Tenant mismatch' })
      return
    }

    ;(req as AuthenticatedRequest).caller = payload
    next()
  }
}
