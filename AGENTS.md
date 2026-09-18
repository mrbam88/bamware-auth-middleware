# AGENTS.md — bamware-auth-middleware

> Read [`../bamware-ai/AGENTS.md`](https://github.com/mrbam88/bamware-ai/blob/main/AGENTS.md)
> first: the Bamware system map (repos, contracts, gates, security).
> This file is `@bamware/auth-middleware` specific.

## What it is

Shared, tested TypeScript package for verifying Bamware access tokens.
Replaces hand-copied `jwt.verify` calls across services and apps (see
`bamware-ai/docs/contracts.md` — the June 2026 token-drift incident this
package exists to prevent).

- **Package name:** `@bamware/auth-middleware`
- **Distribution:** git tag only, not npm. Consumers depend on
  `github:mrbam88/bamware-auth-middleware#v0.1.0`.
- **Build:** `tsup` — ESM + CJS + `.d.ts`.
- **Tests:** `vitest`.
- **This repo is PUBLIC.** No secrets, no PII, ever — see
  `bamware-ai/docs/security.md`. The exported code is generic JWT
  verification; nothing here is Bamware-tenant-specific data.

## Exports

- `TokenPayloadSchema` (zod) / `TokenPayload` (type) — the single source of
  truth for the access-token payload shape. Copied from
  `bamware-auth-service/src/schemas/authSchemas.ts`; that service is
  expected to import it back (follow-up issue).
- `verifyAccessToken(token, { secret, revocationCheck? })`
- `authenticate({ secret, tenantId, revocationCheck? })` — Express
  middleware. 401 on missing/invalid/expired/revoked, 403 on tenant
  mismatch.
- `requireRole(...roles)` — Express middleware, run after `authenticate`.

## Local run

```bash
pnpm install
pnpm build       # tsup — always run before tagging/publishing
pnpm test        # vitest
pnpm typecheck
```

## Versioning

No CI branch protection on this new repo yet — a direct commit to `main`
to bootstrap `v0.1.0` was a one-time exception. From here on: PR + green
CI, then tag.

## Consumers (status)

- `bamware-venue-engine` — adopted (dependency + import smoke test).
- `bamware-auth-service` — NOT yet adopted; tickets #9/#10 are actively
  editing its auth handlers. Follow-up filed on that repo.
- `bamware-dating-service`, `bamware-web` — NOT yet adopted. Follow-ups
  filed on each repo.
