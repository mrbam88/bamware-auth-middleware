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
})

export type TokenPayload = z.infer<typeof TokenPayloadSchema>
