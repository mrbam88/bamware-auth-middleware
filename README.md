# @bamware/auth-middleware

Shared, tested verification for Bamware access tokens — one `TokenPayload`
contract, one `authenticate` Express middleware — instead of each service
and app hand-copying `jwt.verify`.

Why this exists: in June 2026, the matches pagination envelope drifted
between `bamware-auth-service` and its consumers and nothing caught it in
CI on either side (see `bamware-ai/docs/contracts.md`). This package makes
the access-token contract a single, versioned artifact instead of N copies
that can silently disagree.

**This repo is public.** It contains only generic JWT-verification code —
no secrets, no tenant data, no PII. See `bamware-ai/docs/security.md`.

## The contract

```ts
export const TokenPayloadSchema = z.object({
  userId: z.string(),
  email: z.string().email(),
  name: z.string(),
  role: z.enum(['admin', 'owner', 'staff', 'customer']),
  tenantId: z.string(),
  emailVerified: z.boolean().optional(),
})
```

This is the single source of truth, copied from
`bamware-auth-service/src/schemas/authSchemas.ts`. That service is expected
to import it back from this package rather than keep its own copy (tracked
as a follow-up issue — see "Adoption steps" below).

## Install

Not published to npm. Depend on a git tag:

```json
{
  "dependencies": {
    "@bamware/auth-middleware": "github:mrbam88/bamware-auth-middleware#v0.1.0"
  }
}
```

## Usage

```ts
import express from 'express'
import { authenticate, requireRole } from '@bamware/auth-middleware'

const app = express()

app.get(
  '/admin/venues',
  authenticate({ secret: process.env.JWT_SECRET!, tenantId: process.env.TENANT_ID! }),
  requireRole('admin', 'owner'),
  (req, res) => {
    // req.caller: TokenPayload
  },
)
```

`authenticate` responds:
- **401** — missing/malformed `Authorization` header, invalid signature,
  expired token, or (if `revocationCheck` is set) a revoked token.
- **403** — valid token, but `payload.tenantId !== options.tenantId`.

### Revocation hook

```ts
authenticate({
  secret: process.env.JWT_SECRET!,
  tenantId: process.env.TENANT_ID!,
  revocationCheck: async (payload, token) => {
    return isRevoked(payload.userId) // return true to reject
  },
})
```

### Direct verification (no Express)

```ts
import { verifyAccessToken, TokenVerificationError } from '@bamware/auth-middleware'

try {
  const payload = await verifyAccessToken(token, { secret: process.env.JWT_SECRET! })
} catch (err) {
  if (err instanceof TokenVerificationError) {
    // 401
  }
}
```

## Adoption steps for a new consumer

1. Add the dependency: `github:mrbam88/bamware-auth-middleware#v0.1.0`.
2. Replace the hand-copied verify/middleware code with `authenticate` (and
   `requireRole` where a route needs role gating).
3. Add a smoke test that imports `authenticate` and confirms a bad token is
   rejected.
4. Confirm `JWT_SECRET` matches `bamware-auth-service`'s value (unchanged
   by this migration — this package does not rotate secrets).
5. `typecheck` + `test` green, then open a PR referencing the tracking
   issue (`Part of #12 (auth-service)` or the relevant follow-up issue).

**Consumer status:** `bamware-venue-engine` adopted (dependency + import
smoke test). `bamware-auth-service`, `bamware-dating-service`, and
`bamware-web` have follow-up issues filed and are not yet adopted — see
each repo's issue tracker.

## Local development

```bash
pnpm install
pnpm build       # tsup — ESM + CJS + .d.ts, always run before tagging
pnpm test        # vitest — valid/expired/wrong-secret/tenant-mismatch/
                  # role/revocation-hook coverage
pnpm typecheck
```

## Out of scope

Publishing to npm, changing the JWT claims, rotating secrets, and any
deploy — see the tracking issue
[mrbam88/bamware-auth-service#12](https://github.com/mrbam88/bamware-auth-service/issues/12).

## License

MIT
