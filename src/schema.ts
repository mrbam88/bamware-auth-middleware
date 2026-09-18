import { z } from 'zod'

/**
 * Single source of truth for the Bamware access-token payload shape.
 *
 * This is copied verbatim from bamware-auth-service
 * `src/schemas/authSchemas.ts` (TokenPayloadSchema) as of 2026-09-18.
 * auth-service is expected to import this schema back from this package
 * in a follow-up (see README "Adoption steps"), so the two never drift
 * again (contracts.md, June 2026 incident).
 */
export const TokenPayloadSchema = z.object({
  userId: z.string(),
  email: z.string().email(),
  name: z.string(),
  role: z.enum(['admin', 'owner', 'staff', 'customer']),
  tenantId: z.string(),
  // Optional so tokens signed before this field was added still decode.
  // Consumers should treat `undefined` as "unknown / trusted" — don't gate
  // UI on a falsy read when the field isn't present.
  emailVerified: z.boolean().optional(),
  // jti/iat/exp are already on every access token bamware-auth-service signs
  // (via jsonwebtoken's `jwtid` option) — these fields just surface what
  // `jwt.verify()` already decodes. A revocation check (see
  // `RevocationCheck` in verify.ts) needs `jti` on the parsed payload — if
  // this schema didn't list it, zod's default object() strips unknown keys
  // and `payload.jti` would silently be `undefined` for every caller of
  // `verifyAccessToken`, breaking revocation. Added for auth-service#14
  // (bamware-auth-service#10 added these to the canonical schema after this
  // package's schema.ts was first copied from it in #12).
  jti: z.string().optional(),
  iat: z.number().optional(),
  exp: z.number().optional(),
})

export type TokenPayload = z.infer<typeof TokenPayloadSchema>
