import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { logger } from 'hono/logger'
import { prettyJSON } from 'hono/pretty-json'
import { verify, sign } from 'hono/jwt'

/* ============================================================ */
/*  Types                                                       */
/* ============================================================ */

type JWTPayload = {
  sub: string
  email: string
  role?: string
  iat?: number
  exp?: number
  typ?: string
  [key: string]: unknown
}

type Bindings = {
  DB: D1Database
  JWT_SECRET: string
  ENVIRONMENT: string
}

type Variables = {
  user?: any
  apiKey?: {
    id: string
    name: string
    permissions: string[]
  }
}

/* ============================================================ */
/*  JWT utilities (Web Crypto API — Cloudflare Workers native)  */
/* ============================================================ */

const JWT_ACCESS_TTL_MS = 15 * 60 * 1000      // 15 minutes
const JWT_REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000  // 7 days
const OTP_TTL_MS = 10 * 60 * 1000             // 10 minutes

function generateAccessToken(payload: { sub: string; email: string; role: string }, secret: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  return sign(
    {
      ...payload,
      iat: now,
      exp: now + JWT_ACCESS_TTL_MS / 1000,
      typ: 'access',
    },
    secret,
    'HS256'
  )
}

function generateRefreshToken(payload: { sub: string; email: string }, secret: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  return sign(
    {
      ...payload,
      iat: now,
      exp: now + JWT_REFRESH_TTL_MS / 1000,
      typ: 'refresh',
    },
    secret,
    'HS256'
  )
}

async function verifyJWT(token: string, secret: string, expectedType: 'access' | 'refresh'): Promise<any | null> {
  try {
    const payload = await verify(token, secret, 'HS256')
    if (payload.typ !== expectedType) return null
    return payload
  } catch {
    return null
  }
}

/* ============================================================ */
/*  Password hashing (PBKDF2 via Web Crypto API)               */
/* ============================================================ */

async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder()
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  )
  const hashBuf = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' },
    keyMaterial,
    256
  )
  const hashArr = Array.from(new Uint8Array(hashBuf))
  const saltArr = Array.from(salt)
  return `${saltArr.map(b => b.toString(16).padStart(2, '0')).join('')}.${hashArr.map(b => b.toString(16).padStart(2, '0')).join('')}`
}

async function verifyPassword(plain: string, stored: string): Promise<boolean> {
  const [saltHex, hashHex] = stored.split('.')
  if (!saltHex || !hashHex) return false
  const encoder = new TextEncoder()
  const salt = new Uint8Array(saltHex.match(/.{1,2}/g)!.map(b => parseInt(b, 16)))
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(plain),
    'PBKDF2',
    false,
    ['deriveBits']
  )
  const hashBuf = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' },
    keyMaterial,
    256
  )
  const hashArr = Array.from(new Uint8Array(hashBuf))
  const computed = hashArr.map(b => b.toString(16).padStart(2, '0')).join('')
  return computed === hashHex
}

/* ============================================================ */
/*  Secure random helpers                                       */
/* ============================================================ */

function generateOTP(): string {
  const arr = crypto.getRandomValues(new Uint8Array(4))
  const num = (arr[0] << 24 | arr[1] << 16 | arr[2] << 8 | arr[3]) >>> 0
  return (num % 1_000_000).toString().padStart(6, '0')
}

function generateApiKeyPlain(): string {
  const arr = crypto.getRandomValues(new Uint8Array(24))
  return 'sk_live_' + Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('')
}

async function hashApiKey(plainKey: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(plainKey)
  const digest = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('')
}

/* ============================================================ */
/*  Database helpers                                            */
/* ============================================================ */

async function ensureAuthTables(db: D1Database) {
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      id            TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
      email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      role          TEXT NOT NULL DEFAULT 'user',
      created_at    TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `).run()

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id         TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
      user_id    TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `).run()

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS otp_codes (
      id         TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
      email      TEXT NOT NULL COLLATE NOCASE,
      code       TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used       INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `).run()

  // Add user_id column if it doesn't exist (migration for existing DBs)
  try {
    await db.prepare(`ALTER TABLE api_keys ADD COLUMN user_id TEXT`).run()
  } catch {
    // Column already exists
  }

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
      user_id     TEXT NOT NULL,
      name        TEXT NOT NULL,
      key_hash    TEXT NOT NULL UNIQUE,
      permissions TEXT NOT NULL DEFAULT '[]',
      last_used   TEXT,
      created_at  TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at  TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `).run()

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS api_logs (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      endpoint   TEXT NOT NULL,
      method     TEXT NOT NULL,
      ip         TEXT NOT NULL,
      user_id    TEXT,
      api_key_id TEXT,
      status     INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `).run()

  // Items table (existing)
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `).run()

  // Indexes
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`).run()
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_otp_codes_email ON otp_codes(email)`).run()
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_otp_codes_expires ON otp_codes(expires_at)`).run()
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)`).run()
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_api_logs_created ON api_logs(created_at)`).run()
}

async function getUserByEmail(db: D1Database, email: string) {
  return await db.prepare(`SELECT id, email, password_hash, role FROM users WHERE email = ?`).bind(email).first()
}

async function getUserById(db: D1Database, id: string) {
  return await db.prepare(`SELECT id, email, password_hash, role FROM users WHERE id = ?`).bind(id).first()
}

async function createUser(db: D1Database, email: string, passwordHash: string, role = 'user') {
  const res = await db.prepare(
    `INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?) RETURNING id`
  ).bind(email, passwordHash, role).first()
  return res?.id
}

async function storeRefreshToken(db: D1Database, userId: string, tokenHash: string, expiresAt: string) {
  await db.prepare(
    `INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)`
  ).bind(userId, tokenHash, expiresAt).run()
}

async function getRefreshToken(db: D1Database, tokenHash: string) {
  return await db.prepare(`SELECT user_id, expires_at FROM refresh_tokens WHERE token_hash = ?`).bind(tokenHash).first()
}

async function deleteRefreshToken(db: D1Database, tokenHash: string) {
  await db.prepare(`DELETE FROM refresh_tokens WHERE token_hash = ?`).bind(tokenHash).run()
}

async function deleteAllUserRefreshTokens(db: D1Database, userId: string) {
  await db.prepare(`DELETE FROM refresh_tokens WHERE user_id = ?`).bind(userId).run()
}

async function storeOTP(db: D1Database, email: string, code: string, expiresAt: string) {
  await db.prepare(`UPDATE otp_codes SET used = 1 WHERE email = ? AND used = 0`).bind(email).run()
  await db.prepare(
    `INSERT INTO otp_codes (email, code, expires_at) VALUES (?, ?, ?)`
  ).bind(email, code, expiresAt).run()
}

async function verifyOTP(db: D1Database, email: string, code: string) {
  return await db.prepare(
    `SELECT id, expires_at, used FROM otp_codes WHERE email = ? AND code = ? AND used = 0 ORDER BY created_at DESC LIMIT 1`
  ).bind(email, code).first()
}

async function markOTPUsed(db: D1Database, otpId: string) {
  await db.prepare(`UPDATE otp_codes SET used = 1 WHERE id = ?`).bind(otpId).run()
}

async function createApiKeyRow(db: D1Database, userId: string, name: string, keyHash: string, permissions: string[], expiresAt?: string) {
  const res = await db.prepare(
    `INSERT INTO api_keys (user_id, name, key_hash, permissions, expires_at) VALUES (?, ?, ?, ?, ?)`
  ).bind(userId, name, keyHash, JSON.stringify(permissions), expiresAt ?? null).run()
  return res.meta?.last_row_id
}

async function getApiKeyByHash(db: D1Database, keyHash: string) {
  return await db.prepare(`SELECT id, name, key_hash, permissions, expires_at FROM api_keys WHERE key_hash = ?`).bind(keyHash).first()
}

async function updateApiKeyLastUsed(db: D1Database, keyId: string) {
  await db.prepare(`UPDATE api_keys SET last_used = datetime('now') WHERE id = ?`).bind(keyId).run()
}

async function revokeApiKeyRow(db: D1Database, userId: string, keyId: string) {
  await db.prepare(`DELETE FROM api_keys WHERE id = ? AND user_id = ?`).bind(keyId, userId).run()
}

async function logRequest(db: D1Database, endpoint: string, method: string, ip: string, status: number, userId?: string, apiKeyId?: string) {
  try {
    await db.prepare(
      `INSERT INTO api_logs (endpoint, method, ip, user_id, api_key_id, status) VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(endpoint, method, ip, userId ?? null, apiKeyId ?? null, status).run()
  } catch {
    // Logging should never break the request
  }
}

/* ============================================================ */
/*  Sub-routers                                                 */
/* ============================================================ */

/* -- Health -- */
const health = new Hono<{ Bindings: Bindings }>()

health.get('/', (c) => {
  return c.json({
    status: 'ok',
    service: 'universal-api-server',
    version: '2.0.0',
    environment: c.env.ENVIRONMENT || 'cloudflare-workers',
    timestamp: new Date().toISOString(),
  })
})

/* -- Auth -- */
const auth = new Hono<{ Bindings: Bindings; Variables: Variables }>()

auth.get('/', (c) => {
  return c.json({
    module: 'auth',
    version: 'v2',
    status: 'active',
    endpoints: [
      'POST /api/v1/auth/register',
      'POST /api/v1/auth/login',
      'POST /api/v1/auth/refresh',
      'POST /api/v1/auth/logout',
      'GET  /api/v1/auth/me',
      'POST /api/v1/auth/send-otp',
      'POST /api/v1/auth/verify-otp',
    ],
  })
})

// Register
auth.post('/register', async (c) => {
  const { email, password } = await c.req.json<{ email?: string; password?: string }>()
  if (!email || !password) {
    return c.json({ error: 'Email and password required' }, 400)
  }

  await ensureAuthTables(c.env.DB)

  const existing = await getUserByEmail(c.env.DB, email)
  if (existing) {
    return c.json({ error: 'Email already registered' }, 409)
  }

  const passwordHash = await hashPassword(password)
  const userId = await createUser(c.env.DB, email, passwordHash)

  const accessToken = await generateAccessToken({ sub: userId, email, role: 'user' }, c.env.JWT_SECRET)
  const refreshToken = await generateRefreshToken({ sub: userId, email }, c.env.JWT_SECRET)
  const refreshHash = await hashApiKey(refreshToken)
  const refreshExpires = new Date(Date.now() + JWT_REFRESH_TTL_MS).toISOString()
  await storeRefreshToken(c.env.DB, userId, refreshHash, refreshExpires)

  await logRequest(c.env.DB, '/api/v1/auth/register', 'POST', c.req.header('CF-Connecting-IP') ?? 'unknown', 201, userId)

  return c.json({
    status: 'created',
    user: { id: userId, email, role: 'user' },
    access_token: accessToken,
    refresh_token: refreshToken,
    expires_in: JWT_ACCESS_TTL_MS / 1000,
  }, 201)
})

// Login
auth.post('/login', async (c) => {
  const { email, password } = await c.req.json<{ email?: string; password?: string }>()
  if (!email || !password) {
    return c.json({ error: 'Email and password required' }, 400)
  }

  await ensureAuthTables(c.env.DB)

  const user = await getUserByEmail(c.env.DB, email)
  if (!user) {
    return c.json({ error: 'Invalid credentials' }, 401)
  }

  const ok = await verifyPassword(password, user.password_hash)
  if (!ok) {
    return c.json({ error: 'Invalid credentials' }, 401)
  }

  const accessToken = await generateAccessToken({ sub: user.id, email: user.email, role: user.role }, c.env.JWT_SECRET)
  const refreshToken = await generateRefreshToken({ sub: user.id, email: user.email }, c.env.JWT_SECRET)
  const refreshHash = await hashApiKey(refreshToken)
  const refreshExpires = new Date(Date.now() + JWT_REFRESH_TTL_MS).toISOString()
  await storeRefreshToken(c.env.DB, user.id, refreshHash, refreshExpires)

  await logRequest(c.env.DB, '/api/v1/auth/login', 'POST', c.req.header('CF-Connecting-IP') ?? 'unknown', 200, user.id)

  return c.json({
    status: 'ok',
    user: { id: user.id, email: user.email, role: user.role },
    access_token: accessToken,
    refresh_token: refreshToken,
    expires_in: JWT_ACCESS_TTL_MS / 1000,
  })
})

// Refresh
auth.post('/refresh', async (c) => {
  const { refresh_token } = await c.req.json<{ refresh_token?: string }>()
  if (!refresh_token) {
    return c.json({ error: 'Refresh token required' }, 400)
  }

  const refreshHash = await hashApiKey(refresh_token)
  const row = await getRefreshToken(c.env.DB, refreshHash)
  if (!row) {
    return c.json({ error: 'Invalid or expired refresh token' }, 401)
  }

  const expiresAt = new Date(row.expires_at as string)
  if (expiresAt <= new Date()) {
    await deleteRefreshToken(c.env.DB, refreshHash)
    return c.json({ error: 'Refresh token expired' }, 401)
  }

  const user = await getUserById(c.env.DB, row.user_id as string)
  if (!user) {
    return c.json({ error: 'User not found' }, 401)
  }

  // Rotate refresh token
  await deleteRefreshToken(c.env.DB, refreshHash)
  const newRefreshToken = await generateRefreshToken({ sub: user.id, email: user.email }, c.env.JWT_SECRET)
  const newRefreshHash = await hashApiKey(newRefreshToken)
  const newRefreshExpires = new Date(Date.now() + JWT_REFRESH_TTL_MS).toISOString()
  await storeRefreshToken(c.env.DB, user.id, newRefreshHash, newRefreshExpires)

  const accessToken = await generateAccessToken({ sub: user.id, email: user.email, role: user.role }, c.env.JWT_SECRET)

  await logRequest(c.env.DB, '/api/v1/auth/refresh', 'POST', c.req.header('CF-Connecting-IP') ?? 'unknown', 200, user.id)

  return c.json({
    status: 'ok',
    access_token: accessToken,
    refresh_token: newRefreshToken,
    expires_in: JWT_ACCESS_TTL_MS / 1000,
  })
})

// Logout
auth.post('/logout', async (c) => {
  const { refresh_token } = await c.req.json<{ refresh_token?: string }>()
  if (refresh_token) {
    const refreshHash = await hashApiKey(refresh_token)
    await deleteRefreshToken(c.env.DB, refreshHash)
  }
  return c.json({ status: 'logged_out' })
})

// Me (protected)
auth.get('/me', async (c) => {
  const authHeader = c.req.header('Authorization')
  if (!authHeader?.startsWith('Bearer ')) {
    return c.json({ error: 'Missing or invalid Authorization header' }, 401)
  }

  const token = authHeader.slice(7)
  const payload = await verifyJWT(token, c.env.JWT_SECRET, 'access')
  if (!payload) {
    return c.json({ error: 'Invalid or expired token' }, 401)
  }

  return c.json({
    status: 'ok',
    user: {
      id: payload.sub,
      email: payload.email,
      role: payload.role,
    },
  })
})

// Send OTP
auth.post('/send-otp', async (c) => {
  const { email } = await c.req.json<{ email?: string }>()
  if (!email) {
    return c.json({ error: 'Email required' }, 400)
  }

  await ensureAuthTables(c.env.DB)

  const code = generateOTP()
  const expiresAt = new Date(Date.now() + OTP_TTL_MS).toISOString()
  await storeOTP(c.env.DB, email, code, expiresAt)

  await logRequest(c.env.DB, '/api/v1/auth/send-otp', 'POST', c.req.header('CF-Connecting-IP') ?? 'unknown', 200)

  return c.json({
    status: 'otp_sent',
    email,
    otp_code: code, // Development only — remove in production
    expires_in: OTP_TTL_MS / 1000,
  })
})

// Verify OTP
auth.post('/verify-otp', async (c) => {
  const { email, code } = await c.req.json<{ email?: string; code?: string }>()
  if (!email || !code) {
    return c.json({ error: 'Email and code required' }, 400)
  }

  await ensureAuthTables(c.env.DB)

  const otp = await verifyOTP(c.env.DB, email, code)
  if (!otp) {
    return c.json({ error: 'Invalid or expired OTP' }, 401)
  }

  const expiresAt = new Date(otp.expires_at as string)
  if (expiresAt <= new Date()) {
    return c.json({ error: 'OTP expired' }, 401)
  }

  await markOTPUsed(c.env.DB, otp.id as string)

  const user = await getUserByEmail(c.env.DB, email)
  if (!user) {
    return c.json({ error: 'User not found' }, 401)
  }

  const accessToken = await generateAccessToken({ sub: user.id, email: user.email, role: user.role }, c.env.JWT_SECRET)
  const refreshToken = await generateRefreshToken({ sub: user.id, email: user.email }, c.env.JWT_SECRET)
  const refreshHash = await hashApiKey(refreshToken)
  const refreshExpires = new Date(Date.now() + JWT_REFRESH_TTL_MS).toISOString()
  await storeRefreshToken(c.env.DB, user.id, refreshHash, refreshExpires)

  await logRequest(c.env.DB, '/api/v1/auth/verify-otp', 'POST', c.req.header('CF-Connecting-IP') ?? 'unknown', 200, user.id)

  return c.json({
    status: 'ok',
    user: { id: user.id, email: user.email, role: user.role },
    access_token: accessToken,
    refresh_token: refreshToken,
    expires_in: JWT_ACCESS_TTL_MS / 1000,
  })
})

/* -- API Keys (service-to-service) -- */
const apiKeys = new Hono<{ Bindings: Bindings; Variables: Variables }>()

apiKeys.use('*', jwtAuth)

apiKeys.get('/', async (c) => {
  const user = c.get('user')
  if (!user) {
    return c.json({ error: 'Unauthorized' }, 401)
  }

  await ensureAuthTables(c.env.DB)

  const keys = await c.env.DB.prepare(
    `SELECT id, name, key_hash, permissions, last_used, created_at, expires_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC`
  ).bind(user.sub).all()

  const keyList = (keys.results || []).map((k: any) => ({
    id: k.id,
    name: k.name,
    key_hash: k.key_hash,
    permissions: typeof k.permissions === 'string' ? JSON.parse(k.permissions) : k.permissions,
    last_used: k.last_used,
    created_at: k.created_at,
    expires_at: k.expires_at,
    // Mask the hash for display
    key_prefix: 'sk_live_' + k.key_hash.substring(0, 8) + '...',
  }))

  return c.json({
    status: 'ok',
    keys: keyList,
    note: 'Keys are shown with masked hashes. Plaintext keys are shown only at creation time.',
  })
})

apiKeys.post('/', async (c) => {
  const user = c.get('user')
  if (!user) {
    return c.json({ error: 'Unauthorized' }, 401)
  }

  await ensureAuthTables(c.env.DB)

  const { name, permissions, expires_in_days } = await c.req.json<{
    name?: string
    permissions?: string[]
    expires_in_days?: number
  }>()

  const plainKey = generateApiKeyPlain()
  const keyHash = await hashApiKey(plainKey)
  const perms = permissions ?? ['read']
  const expiresAt = expires_in_days ? new Date(Date.now() + expires_in_days * 24 * 60 * 60 * 1000).toISOString() : null

  await createApiKeyRow(c.env.DB, user.sub, name ?? 'unnamed-key', keyHash, perms, expiresAt)

  await logRequest(c.env.DB, '/api/v1/auth/api-keys', 'POST', c.req.header('CF-Connecting-IP') ?? 'unknown', 201, user.sub)

  return c.json({
    status: 'created',
    name: name ?? 'unnamed-key',
    key: plainKey,
    permissions: perms,
    expires_at: expiresAt,
    warning: 'Save this key now. It cannot be recovered again.',
  }, 201)
})

apiKeys.delete('/:id', async (c) => {
  const user = c.get('user')
  if (!user) {
    return c.json({ error: 'Unauthorized' }, 401)
  }
  const id = c.req.param('id')
  await revokeApiKeyRow(c.env.DB, user.sub, id)
  await logRequest(c.env.DB, '/api/v1/auth/api-keys/:id', 'DELETE', c.req.header('CF-Connecting-IP') ?? 'unknown', 200, user.sub)
  return c.json({ status: 'revoked', id })
})

/* -- Project Alpha (sandbox, protected) -- */
const projectAlpha = new Hono<{ Bindings: Bindings; Variables: Variables }>()
projectAlpha.use('*', authOrApiKey)

projectAlpha.get('/', async (c) => {
  const user = c.get('user')
  const apiKey = c.get('apiKey')
  return c.json({
    project: 'alpha',
    status: 'sandbox',
    version: 'v2',
    authenticated: !!user || !!apiKey,
    user: user ? { id: user.sub, email: user.email } : null,
    service: apiKey ? { name: apiKey.name, permissions: apiKey.permissions } : null,
  })
})

projectAlpha.get('/items', async (c) => {
  const user = c.get('user')
  const apiKey = c.get('apiKey')
  if (!user && !apiKey) {
    return c.json({ error: 'Unauthorized' }, 401)
  }
  return c.json({ project: 'alpha', items: [], count: 0 })
})

projectAlpha.post('/items', async (c) => {
  const user = c.get('user')
  const apiKey = c.get('apiKey')
  if (!user && !apiKey) {
    return c.json({ error: 'Unauthorized' }, 401)
  }
  const body = await c.req.json<{ name?: string }>()
  return c.json(
    { project: 'alpha', item: { id: Date.now(), name: body.name ?? 'untitled' }, created: true },
    201
  )
})

/* -- Project Beta (sandbox, protected) -- */
const projectBeta = new Hono<{ Bindings: Bindings; Variables: Variables }>()
projectBeta.use('*', authOrApiKey)

projectBeta.get('/', async (c) => {
  const user = c.get('user')
  const apiKey = c.get('apiKey')
  return c.json({
    project: 'beta',
    status: 'sandbox',
    version: 'v2',
    authenticated: !!user || !!apiKey,
    user: user ? { id: user.sub, email: user.email } : null,
    service: apiKey ? { name: apiKey.name, permissions: apiKey.permissions } : null,
  })
})

projectBeta.get('/items', async (c) => {
  const user = c.get('user')
  const apiKey = c.get('apiKey')
  if (!user && !apiKey) {
    return c.json({ error: 'Unauthorized' }, 401)
  }
  return c.json({ project: 'beta', items: [], count: 0 })
})

projectBeta.post('/items', async (c) => {
  const user = c.get('user')
  const apiKey = c.get('apiKey')
  if (!user && !apiKey) {
    return c.json({ error: 'Unauthorized' }, 401)
  }
  const body = await c.req.json<{ name?: string }>()
  return c.json(
    { project: 'beta', item: { id: Date.now(), name: body.name ?? 'untitled' }, created: true },
    201
  )
})

/* -- Database (D1) -- */
const database = new Hono<{ Bindings: Bindings }>()

database.get('/_init', async (c) => {
  await ensureAuthTables(c.env.DB)
  return c.json({ status: 'tables_ready' })
})

database.get('/items', async (c) => {
  const { results } = await c.env.DB.prepare('SELECT * FROM items ORDER BY id DESC').all()
  return c.json({ items: results, count: results?.length || 0 })
})

database.post('/items', async (c) => {
  const body = await c.req.json<{ name?: string }>()
  const result = await c.env.DB.prepare(`INSERT INTO items (name) VALUES (?)`).bind(body.name ?? 'untitled').run()
  return c.json({
    id: result.meta?.last_row_id,
    name: body.name ?? 'untitled',
    created: true,
  }, 201)
})

database.get('/items/:id', async (c) => {
  const id = c.req.param('id')
  const item = await c.env.DB.prepare('SELECT * FROM items WHERE id = ?').bind(id).first()
  if (!item) {
    return c.json({ error: 'Item not found' }, 404)
  }
  return c.json({ item })
})

database.delete('/items/:id', async (c) => {
  const id = c.req.param('id')
  await c.env.DB.prepare('DELETE FROM items WHERE id = ?').bind(id).run()
  return c.json({ deleted: true, id })
})

/* ============================================================ */
/*  Middleware                                                  */
/* ============================================================ */

const rateLimitStore = new Map<string, { count: number; resetAt: number }>()
const RATE_LIMIT_MAX = 100
const RATE_LIMIT_WINDOW_MS = 60 * 1000

function rateLimitMiddleware() {
  return async (c: any, next: any) => {
    const ip = c.req.header('CF-Connecting-IP') ?? c.req.header('x-real-ip') ?? 'unknown'
    const now = Date.now()
    const entry = rateLimitStore.get(ip)

    if (!entry || now > entry.resetAt) {
      rateLimitStore.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS })
    } else {
      entry.count++
      if (entry.count > RATE_LIMIT_MAX) {
        return c.json({ error: 'Too many requests', retry_after: Math.ceil((entry.resetAt - now) / 1000) }, 429)
      }
    }

    await next()
  }
}

async function requestLogMiddleware(c: any, next: any) {
  await next()
  const status = c.res.status
  const ip = c.req.header('CF-Connecting-IP') ?? c.req.header('x-real-ip') ?? 'unknown'
  const endpoint = c.req.path
  const method = c.req.method
  const user = c.get('user')
  const apiKey = c.get('apiKey')

  try {
    await logRequest(c.env.DB, endpoint, method, ip, status, user?.sub, apiKey?.id)
  } catch {
    // Logging failures are non-fatal
  }
}

async function jwtAuth(c: any, next: any) {
  const authHeader = c.req.header('Authorization')
  if (!authHeader?.startsWith('Bearer ')) {
    await next()
    return
  }

  const token = authHeader.slice(7)
  const payload = await verifyJWT(token, c.env.JWT_SECRET, 'access')
  if (!payload) {
    return c.json({ error: 'Invalid or expired token' }, 401)
  }

  c.set('user', payload)
  await next()
}

async function apiKeyAuth(c: any, next: any) {
  const keyHeader = c.req.header('X-API-Key')
  if (!keyHeader) {
    await next()
    return
  }

  const keyHash = await hashApiKey(keyHeader)
  const row = await getApiKeyByHash(c.env.DB, keyHash)
  if (!row) {
    return c.json({ error: 'Invalid API key' }, 401)
  }

  const expiresAt = row.expires_at ? new Date(row.expires_at as string) : null
  if (expiresAt && expiresAt <= new Date()) {
    return c.json({ error: 'API key expired' }, 401)
  }

  const permissions = typeof row.permissions === 'string' ? JSON.parse(row.permissions) : (row.permissions as string[])

  c.set('apiKey', {
    id: row.id,
    name: row.name,
    permissions,
  })

  await updateApiKeyLastUsed(c.env.DB, row.id)
  await next()
}

async function authOrApiKey(c: any, next: any) {
  const authHeader = c.req.header('Authorization')
  const keyHeader = c.req.header('X-API-Key')

  if (!authHeader?.startsWith('Bearer ') && !keyHeader) {
    return c.json({ error: 'Missing Authorization header or X-API-Key' }, 401)
  }

  // Try JWT first
  if (authHeader?.startsWith('Bearer ')) {
    const token = authHeader.slice(7)
    const payload = await verifyJWT(token, c.env.JWT_SECRET, 'access')
    if (payload) {
      c.set('user', payload)
      await next()
      return
    }
  }

  // Try API key
  if (keyHeader) {
    const keyHash = await hashApiKey(keyHeader)
    const row = await getApiKeyByHash(c.env.DB, keyHash)
    if (!row) {
      return c.json({ error: 'Invalid API key' }, 401)
    }
    const expiresAt = row.expires_at ? new Date(row.expires_at as string) : null
    if (expiresAt && expiresAt <= new Date()) {
      return c.json({ error: 'API key expired' }, 401)
    }
    const permissions = typeof row.permissions === 'string' ? JSON.parse(row.permissions) : (row.permissions as string[])
    c.set('apiKey', { id: row.id, name: row.name, permissions })
    await updateApiKeyLastUsed(c.env.DB, row.id)
    await next()
    return
  }

  return c.json({ error: 'Unauthorized' }, 401)
}

/* ============================================================ */
/*  Main app                                                    */
/* ============================================================ */

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Global middleware
app.use('*', logger())
app.use('*', cors({ origin: '*' }))
app.use('*', prettyJSON())
app.use('*', rateLimitMiddleware())
app.use('*', requestLogMiddleware)

// Ensure auth tables on every cold start (idempotent)
app.use('*', async (c, next) => {
  try {
    await ensureAuthTables(c.env.DB)
  } catch {
    // Table creation is best-effort; individual endpoints also call it
  }
  await next()
})

// Global error handler
app.onError((err, c) => {
  console.error('[API ERROR]', err)
  return c.json(
    {
      error: 'Internal Server Error',
      message: err instanceof Error ? err.message : String(err),
    },
    500
  )
})

app.notFound((c) => {
  return c.json({ error: 'Not Found', path: c.req.path }, 404)
})

// Route mounting
app.route('/', health)
app.route('/api/v1/auth', auth)
app.route('/api/v1/auth/api-keys', apiKeys)
app.route('/api/v1/project-alpha', projectAlpha)
app.route('/api/v1/project-beta', projectBeta)
app.route('/api/v1/db', database)

export default app
