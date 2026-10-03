import jwt from 'jsonwebtoken'
import { describe, expect, it, vi } from 'vitest'
import { TokenVerificationError, verifyAccessToken } from '../src/verify.js'
import type { TokenPayload } from '../src/schema.js'

const SECRET = 'test-secret'

const payload: TokenPayload = {
  userId: 'user-1',
  email: 'user@example.com',
  name: 'Test User',
  role: 'customer',
  tenantId: 'tenant-a',
  emailVerified: true,
}

function sign(overrides: Partial<jwt.SignOptions> = {}, body: object = payload) {
  return jwt.sign(body, SECRET, { expiresIn: '15m', ...overrides })
}

describe('verifyAccessToken', () => {
  it('returns the payload for a valid token', async () => {
    const token = sign()
    const result = await verifyAccessToken(token, { secret: SECRET })
    expect(result).toMatchObject(payload)
  })

  it('rejects an expired token', async () => {
    const token = sign({ expiresIn: '-1s' })
    await expect(verifyAccessToken(token, { secret: SECRET })).rejects.toThrow(
      TokenVerificationError,
    )
  })

  it('rejects a token signed with the wrong secret', async () => {
    const token = jwt.sign(payload, 'a-different-secret', { expiresIn: '15m' })
    await expect(verifyAccessToken(token, { secret: SECRET })).rejects.toThrow(
      TokenVerificationError,
    )
  })

  it('rejects a token whose payload does not match TokenPayloadSchema', async () => {
    const token = sign({}, { userId: 'user-1' })
    await expect(verifyAccessToken(token, { secret: SECRET })).rejects.toThrow(
      TokenVerificationError,
    )
  })

  it('calls the revocation hook and rejects when it reports revoked', async () => {
    const token = sign()
    const revocationCheck = vi.fn().mockResolvedValue(true)
    await expect(
      verifyAccessToken(token, { secret: SECRET, revocationCheck }),
    ).rejects.toThrow(TokenVerificationError)
    expect(revocationCheck).toHaveBeenCalledTimes(1)
    expect(revocationCheck).toHaveBeenCalledWith(expect.objectContaining({ userId: 'user-1' }), token)
  })

  it('calls the revocation hook and allows when it reports not revoked', async () => {
    const token = sign()
    const revocationCheck = vi.fn().mockResolvedValue(false)
    const result = await verifyAccessToken(token, { secret: SECRET, revocationCheck })
    expect(result).toMatchObject(payload)
    expect(revocationCheck).toHaveBeenCalledTimes(1)
  })

  it('surfaces jti on the parsed payload and passes it to the revocation hook', async () => {
    // A revocation check keys on `jti` (single-token revoke, e.g. logout) —
    // this pins that the schema doesn't strip it out from under callers.
    const token = sign({ jwtid: 'access-jti-1' })
    const revocationCheck = vi.fn().mockResolvedValue(false)
    const result = await verifyAccessToken(token, { secret: SECRET, revocationCheck })
    expect(result.jti).toBe('access-jti-1')
    expect(typeof result.iat).toBe('number')
    expect(typeof result.exp).toBe('number')
    expect(revocationCheck).toHaveBeenCalledWith(
      expect.objectContaining({ jti: 'access-jti-1' }),
      token,
    )
  })
})


describe('credential version and token purpose', () => {
  it('preserves version zero and later versions for revocation checks', async () => {
    for (const authVersion of [0, 1, 42, Number.MAX_SAFE_INTEGER]) {
      const token = sign({}, { ...payload, authVersion, tokenType: 'access' })
      const revocationCheck = vi.fn().mockResolvedValue(false)
      const result = await verifyAccessToken(token, { secret: SECRET, revocationCheck })
      expect(result.authVersion).toBe(authVersion)
      expect(result.tokenType).toBe('access')
      expect(revocationCheck).toHaveBeenCalledWith(expect.objectContaining({ authVersion, tokenType: 'access' }), token)
    }
  })

  it.each([-1, 1.5, '1', null, Number.MAX_SAFE_INTEGER + 1])('rejects malformed version %s before the hook', async (authVersion) => {
    const revocationCheck = vi.fn()
    await expect(verifyAccessToken(sign({}, { ...payload, authVersion }), { secret: SECRET, revocationCheck })).rejects.toThrow(TokenVerificationError)
    expect(revocationCheck).not.toHaveBeenCalled()
  })

  it('checks signature before passing version claims to the hook', async () => {
    const revocationCheck = vi.fn()
    const token = jwt.sign({ ...payload, authVersion: 7, tokenType: 'access' }, 'wrong-secret')
    await expect(verifyAccessToken(token, { secret: SECRET, revocationCheck })).rejects.toThrow(TokenVerificationError)
    expect(revocationCheck).not.toHaveBeenCalled()
  })

  it.each(['refresh', 'reset', '', null])('rejects non-access purpose %s before the hook', async (tokenType) => {
    const revocationCheck = vi.fn()
    await expect(verifyAccessToken(sign({}, { ...payload, tokenType }), { secret: SECRET, revocationCheck })).rejects.toThrow(TokenVerificationError)
    expect(revocationCheck).not.toHaveBeenCalled()
  })

  it('preserves absent legacy claims rather than silently assigning a generation', async () => {
    const result = await verifyAccessToken(sign(), { secret: SECRET })
    expect(result).not.toHaveProperty('authVersion')
    expect(result).not.toHaveProperty('tokenType')
  })

  it('propagates hook failures without returning an authenticated payload', async () => {
    await expect(verifyAccessToken(sign({}, { ...payload, authVersion: 1 }), { secret: SECRET, revocationCheck: async () => { throw new Error('lookup unavailable') } })).rejects.toThrow('lookup unavailable')
  })
})
