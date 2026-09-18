export { TokenPayloadSchema, type TokenPayload } from './schema.js'
export {
  verifyAccessToken,
  TokenVerificationError,
  type VerifyAccessTokenOptions,
  type RevocationCheck,
} from './verify.js'
export {
  authenticate,
  type AuthenticateOptions,
  type AuthenticatedRequest,
} from './middleware.js'
export { requireRole } from './requireRole.js'
