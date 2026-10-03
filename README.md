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
  jti: z.string().optional(),
  iat: z.number().optional(),
  exp: z.number().optional(),
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


## Why `dist/` is committed

Consumers install this package straight from a git tag. Lambda packaging (`npm install --production --ignore-scripts`) and some CI installs never run `prepare`, so the built output is committed alongside the source. Rebuild (`pnpm build`) and commit `dist/` in the same change whenever `src/` changes; tag the release.

## Proposed v0.1.3: credential generations and token purpose

Coordinated work: `mrbam88/bamware-ai#85`. This proposal does not revoke any
session by itself and does not release a tag or change deployed consumers.

- `authVersion?: number`: nonnegative **safe integer**. Zero is valid. Unknown
  fields are still stripped, but this field is retained in the verified
  payload and passed to the existing revocation callback.
- `tokenType?: 'access' | 'refresh'`: the shared schema understands both
  purposes. `verifyAccessToken` accepts only explicit `access` or a missing
  legacy purpose; it rejects explicit `refresh` before invoking the hook.
- Missing legacy claims stay missing. This library does not equate an absent
  generation with zero. Consumers must agree on their legacy migration
  policy and compare credential generations against authoritative user state.
- Signature/expiry and payload validation precede the revocation callback.
  Hook failures propagate; they never return a verified user.

The existing `revocationCheck(payload, token)` API is unchanged. A consumer
without a revocation check still cannot detect a user's password reset.
Refresh-token verification remains the issuer's responsibility: it must
reject explicit access purpose, enforce its legacy policy, and check the
current generation/refresh-token record before rotating credentials.

### Coordinated rollout

Proposed immutable git version: **v0.1.3**. Merge a reviewed, green PR, then
publish that tag only after auth-service and every access-token consumer
agree on purpose/generation semantics. Consumers must pin the release tag
(or an exact reviewed commit for integration tests); do not move tags.
The checked-in ESM/CJS/declarations are rebuilt because git consumers can
install with scripts disabled. No tag or package release is part of this PR.

Rollout must inventory old tokens, user generations, access/refresh issuance,
revocation callbacks, session caches, and all admin/Assistant consumers.
Rolling back to middleware/consumers that omit the generation check can
resurrect revoked credentials; preserving database generations alone does
not make that rollback safe. Coordinate a fail-closed or token-invalidation
rollback before production adoption.
