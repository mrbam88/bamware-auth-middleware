"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  TokenPayloadSchema: () => TokenPayloadSchema,
  TokenVerificationError: () => TokenVerificationError,
  authenticate: () => authenticate,
  requireRole: () => requireRole,
  verifyAccessToken: () => verifyAccessToken
});
module.exports = __toCommonJS(index_exports);

// src/schema.ts
var import_zod = require("zod");
var TokenPayloadSchema = import_zod.z.object({
  userId: import_zod.z.string(),
  email: import_zod.z.string().email(),
  name: import_zod.z.string(),
  role: import_zod.z.enum(["admin", "owner", "staff", "customer"]),
  tenantId: import_zod.z.string(),
  // Optional so tokens signed before this field was added still decode.
  // Consumers should treat `undefined` as "unknown / trusted" — don't gate
  // UI on a falsy read when the field isn't present.
  emailVerified: import_zod.z.boolean().optional(),
  // jti/iat/exp are already on every access token bamware-auth-service signs
  // (via jsonwebtoken's `jwtid` option) — these fields just surface what
  // `jwt.verify()` already decodes. A revocation check (see
  // `RevocationCheck` in verify.ts) needs `jti` on the parsed payload — if
  // this schema didn't list it, zod's default object() strips unknown keys
  // and `payload.jti` would silently be `undefined` for every caller of
  // `verifyAccessToken`, breaking revocation. Added for auth-service#14
  // (bamware-auth-service#10 added these to the canonical schema after this
  // package's schema.ts was first copied from it in #12).
  jti: import_zod.z.string().optional(),
  iat: import_zod.z.number().optional(),
  exp: import_zod.z.number().optional()
});

// src/verify.ts
var import_jsonwebtoken = __toESM(require("jsonwebtoken"), 1);
var TokenVerificationError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "TokenVerificationError";
  }
};
async function verifyAccessToken(token, options) {
  let decoded;
  try {
    decoded = import_jsonwebtoken.default.verify(token, options.secret);
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
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  TokenPayloadSchema,
  TokenVerificationError,
  authenticate,
  requireRole,
  verifyAccessToken
});
//# sourceMappingURL=index.cjs.map