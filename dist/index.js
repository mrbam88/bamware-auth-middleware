// src/schema.ts
import { z } from "zod";
var TokenPayloadSchema = z.object({
  userId: z.string(),
  email: z.string().email(),
  name: z.string(),
  role: z.enum(["admin", "owner", "staff", "customer"]),
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
  exp: z.number().optional()
});

// src/verify.ts
import jwt from "jsonwebtoken";
var TokenVerificationError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "TokenVerificationError";
  }
};
async function verifyAccessToken(token, options) {
  let decoded;
  try {
    decoded = jwt.verify(token, options.secret);
  } catch {
    throw new TokenVerificationError("Invalid or expired token");
  }
  const result = TokenPayloadSchema.safeParse(decoded);
  if (!result.success) {
    throw new TokenVerificationError("Invalid token payload");
  }
  if (options.revocationCheck) {
    const revoked = await options.revocationCheck(result.data, token);
    if (revoked) {
      throw new TokenVerificationError("Token has been revoked");
    }
  }
  return result.data;
}

// src/middleware.ts
function authenticate(options) {
  return async function authenticateMiddleware(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth?.startsWith("Bearer ")) {
      res.status(401).json({ error: "Missing or invalid authorization header" });
      return;
    }
    const token = auth.slice(7);
    let payload;
    try {
      payload = await verifyAccessToken(token, {
        secret: options.secret,
        revocationCheck: options.revocationCheck
      });
    } catch {
      res.status(401).json({ error: "Invalid or expired token" });
      return;
    }
    if (payload.tenantId !== options.tenantId) {
      res.status(403).json({ error: "Tenant mismatch" });
      return;
    }
    ;
    req.caller = payload;
    next();
  };
}

// src/requireRole.ts
function requireRole(...roles) {
  return function requireRoleMiddleware(req, res, next) {
    const caller = req.caller;
    if (!caller || !roles.includes(caller.role)) {
      res.status(403).json({ error: "Insufficient role" });
      return;
    }
    next();
  };
}
export {
  TokenPayloadSchema,
  TokenVerificationError,
  authenticate,
  requireRole,
  verifyAccessToken
};
//# sourceMappingURL=index.js.map