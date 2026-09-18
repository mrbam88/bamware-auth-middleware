import { z } from 'zod';
import { Request, Response, NextFunction } from 'express';

/**
 * Single source of truth for the Bamware access-token payload shape.
 *
 * This is copied verbatim from bamware-auth-service
 * `src/schemas/authSchemas.ts` (TokenPayloadSchema) as of 2026-09-18.
 * auth-service is expected to import this schema back from this package
 * in a follow-up (see README "Adoption steps"), so the two never drift
 * again (contracts.md, June 2026 incident).
 */
declare const TokenPayloadSchema: z.ZodObject<{
    userId: z.ZodString;
    email: z.ZodString;
    name: z.ZodString;
    role: z.ZodEnum<["admin", "owner", "staff", "customer"]>;
    tenantId: z.ZodString;
    emailVerified: z.ZodOptional<z.ZodBoolean>;
    jti: z.ZodOptional<z.ZodString>;
    iat: z.ZodOptional<z.ZodNumber>;
    exp: z.ZodOptional<z.ZodNumber>;
}, "strip", z.ZodTypeAny, {
    userId: string;
    email: string;
    name: string;
    role: "admin" | "owner" | "staff" | "customer";
    tenantId: string;
    emailVerified?: boolean | undefined;
    jti?: string | undefined;
    iat?: number | undefined;
    exp?: number | undefined;
}, {
    userId: string;
    email: string;
    name: string;
    role: "admin" | "owner" | "staff" | "customer";
    tenantId: string;
    emailVerified?: boolean | undefined;
    jti?: string | undefined;
    iat?: number | undefined;
    exp?: number | undefined;
}>;
type TokenPayload = z.infer<typeof TokenPayloadSchema>;

/**
 * Optional hook to reject an otherwise-valid, unexpired token — e.g. because
 * the user's session or the token's `jti` was revoked. Return `true` to
 * reject (revoked), `false`/`undefined` to allow. May be async (DB/cache
 * lookup).
 */
type RevocationCheck = (payload: TokenPayload, token: string) => boolean | Promise<boolean>;
interface VerifyAccessTokenOptions {
    /** HS256 signing secret. Must match the value bamware-auth-service signs with. */
    secret: string;
    revocationCheck?: RevocationCheck;
}
declare class TokenVerificationError extends Error {
    constructor(message: string);
}
/**
 * Verify a Bamware access token's signature, expiry, and payload shape.
 *
 * Throws `TokenVerificationError` when the token is missing, malformed,
 * expired, signed with a different secret, has a payload that doesn't match
 * `TokenPayloadSchema`, or is rejected by `revocationCheck`.
 */
declare function verifyAccessToken(token: string, options: VerifyAccessTokenOptions): Promise<TokenPayload>;

interface AuthenticatedRequest extends Request {
    caller: TokenPayload;
}
interface AuthenticateOptions {
    /** HS256 signing secret. Must match the value bamware-auth-service signs with. */
    secret: string;
    /** Reject (403) any token whose `tenantId` doesn't match this value. */
    tenantId: string;
    revocationCheck?: RevocationCheck;
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
declare function authenticate(options: AuthenticateOptions): (req: Request, res: Response, next: NextFunction) => Promise<void>;

/**
 * Express middleware factory: requires `req.caller.role` (set by
 * `authenticate()`, which must run first) to be one of `roles`.
 *
 * 403 when `authenticate()` hasn't run (no `req.caller`) or the caller's
 * role isn't allowed.
 */
declare function requireRole(...roles: TokenPayload['role'][]): (req: Request, res: Response, next: NextFunction) => void;

export { type AuthenticateOptions, type AuthenticatedRequest, type RevocationCheck, type TokenPayload, TokenPayloadSchema, TokenVerificationError, type VerifyAccessTokenOptions, authenticate, requireRole, verifyAccessToken };
