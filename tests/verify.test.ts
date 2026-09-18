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
})
