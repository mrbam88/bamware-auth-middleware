import type { NextFunction, Request, Response } from 'express'
import type { AuthenticatedRequest } from './middleware.js'
import type { TokenPayload } from './schema.js'

/**
 * Express middleware factory: requires `req.caller.role` (set by
 * `authenticate()`, which must run first) to be one of `roles`.
 *
 * 403 when `authenticate()` hasn't run (no `req.caller`) or the caller's
 * role isn't allowed.
 */
export function requireRole(...roles: TokenPayload['role'][]) {
  return function requireRoleMiddleware(req: Request, res: Response, next: NextFunction): void {
    const caller = (req as AuthenticatedRequest).caller
    if (!caller || !roles.includes(caller.role)) {
      res.status(403).json({ error: 'Insufficient role' })
      return
    }
    next()
  }
}
