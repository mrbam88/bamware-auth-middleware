import jwt from 'jsonwebtoken'
import { describe, expect, it, vi } from 'vitest'
import express from 'express'
import request from 'supertest'
import { authenticate, type AuthenticatedRequest } from '../src/middleware.js'
import { requireRole } from '../src/requireRole.js'
import type { TokenPayload } from '../src/schema.js'

const SECRET = 'test-secret'

const payload: TokenPayload = {
  userId: 'user-1',
  email: 'user@example.com',
  name: 'Test User',
  role: 'customer',
  tenantId: 'tenant-a',
}

function sign(body: object = payload, expiresIn: jwt.SignOptions['expiresIn'] = '15m') {
  return jwt.sign(body, SECRET, { expiresIn })
}

function buildApp(opts: Parameters<typeof authenticate>[0]) {
  const app = express()
  app.get('/whoami', authenticate(opts), (req, res) => {
    res.json((req as AuthenticatedRequest).caller)
  })
  app.get(
    '/admin-only',
    authenticate(opts),
    requireRole('admin', 'owner'),
    (_req, res) => {
      res.json({ ok: true })
    },
  )
  return app
}

describe('authenticate middleware', () => {
  it('401s on a missing Authorization header', async () => {
    const app = buildApp({ secret: SECRET, tenantId: 'tenant-a' })
    const res = await request(app).get('/whoami')
    expect(res.status).toBe(401)
  })

  it('401s on an invalid/expired token', async () => {
    const app = buildApp({ secret: SECRET, tenantId: 'tenant-a' })
    const token = sign(payload, '-1s')
    const res = await request(app).get('/whoami').set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(401)
  })

  it('403s on a tenant mismatch', async () => {
    const app = buildApp({ secret: SECRET, tenantId: 'tenant-b' })
    const token = sign()
    const res = await request(app).get('/whoami').set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(403)
  })

  it('sets req.caller and calls next() on a valid, matching-tenant token', async () => {
    const app = buildApp({ secret: SECRET, tenantId: 'tenant-a' })
    const token = sign()
    const res = await request(app).get('/whoami').set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(200)
    expect(res.body).toMatchObject(payload)
  })

  it('invokes the revocation hook via the middleware', async () => {
    const revocationCheck = vi.fn().mockResolvedValue(false)
    const app = buildApp({ secret: SECRET, tenantId: 'tenant-a', revocationCheck })
    const token = sign()
    const res = await request(app).get('/whoami').set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(200)
    expect(revocationCheck).toHaveBeenCalledTimes(1)
  })
})

describe('requireRole middleware', () => {
  it('403s when the caller role is not allowed', async () => {
    const app = buildApp({ secret: SECRET, tenantId: 'tenant-a' })
    const token = sign() // role: customer
    const res = await request(app).get('/admin-only').set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(403)
  })

  it('allows through when the caller role is allowed', async () => {
    const app = buildApp({ secret: SECRET, tenantId: 'tenant-a' })
    const token = sign({ ...payload, role: 'admin' })
    const res = await request(app).get('/admin-only').set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(200)
  })
})
