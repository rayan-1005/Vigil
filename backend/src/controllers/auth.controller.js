// src/controllers/auth.controller.js
// SECURITY IMPROVEMENTS over original spec:
//   1. bcrypt cost factor 12 (configurable via BCRYPT_ROUNDS env)
//   2. Short-lived access tokens (15m) + refresh tokens (7d)
//   3. Logout revokes the access token's jti in Redis
//   4. Generic error messages to prevent user enumeration
//   5. API key hashed (HMAC-SHA256) before storage

'use strict';

const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const db = require('../config/database');
const env = require('../config/env');
const ApiError = require('../utils/apiError');
const { issueTokens, revokeToken } = require('../middleware/auth');
const { generateApiKey, hashApiKey } = require('../utils/crypto');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

// Pre-compute a valid bcrypt hash for timing-safe comparison when user is not found.
// This avoids early-return leaking whether an email exists via response-time differences.
const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), 12);

async function register(req, res, next) {
  try {
    const { name, email, password } = req.body;
    // SECURITY: Force role to 'institution' — admin accounts must be created
    // through a separate, secured process (e.g. DB seed or admin-only endpoint).
    const role = 'institution';

    // Hash password with configurable cost factor
    const passwordHash = await bcrypt.hash(password, env.BCRYPT_ROUNDS);

    // Generate API key – return plaintext once, store hash
    const plainKey = generateApiKey();
    const hashedKey = hashApiKey(plainKey);

    const { rows } = await db.query(
      `INSERT INTO institutions (id, name, email, password_hash, role, api_key)
       VALUES (gen_random_uuid(), $1, $2, $3, $4, $5)
       RETURNING id, name, email, role, created_at`,
      [name, email, passwordHash, role, hashedKey]
    );

    const institution = rows[0];

    return res.status(201).json({
      success: true,
      data: {
        id:         institution.id,
        name:       institution.name,
        email:      institution.email,
        role:       institution.role,
        createdAt:  institution.created_at,
        // API key shown ONCE – cannot be recovered; store it securely
        apiKey:     plainKey,
        apiKeyNote: 'Store this key securely. It will not be shown again.',
      },
    });
  } catch (err) {
    next(err);
  }
}

async function login(req, res, next) {
  try {
    const { email, password } = req.body;

    const { rows } = await db.query(
      `SELECT id, password_hash, role, is_active FROM institutions WHERE email = $1 LIMIT 1`,
      [email]
    );

    // SECURITY: Use constant-time bcrypt compare even when user not found
    // to prevent timing-based user enumeration.
    const institution = rows[0];
    const hashToCompare = institution ? institution.password_hash : DUMMY_HASH;

    const passwordValid = await bcrypt.compare(password, hashToCompare);

    if (!institution || !passwordValid || !institution.is_active) {
      // Generic message – don't reveal whether email exists or account is inactive
      return next(ApiError.unauthorized('Invalid credentials'));
    }

    const { accessToken, refreshToken } = issueTokens(institution.id, institution.role);

    // httpOnly + Secure refresh token cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure:   env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge:   7 * 24 * 60 * 60 * 1000, // 7 days in ms
      path:     '/api/v1/auth/refresh',
    });

    return res.json({
      success:     true,
      accessToken,
      expiresIn:   env.JWT_ACCESS_EXPIRES_IN,
    });
  } catch (err) {
    next(err);
  }
}

async function refresh(req, res, next) {
  try {
    // Accept from httpOnly cookie (preferred) or body (fallback for mobile clients)
    const token = req.cookies?.refreshToken ?? req.body?.refreshToken;

    if (!token) {
      return next(ApiError.unauthorized('Refresh token required'));
    }

    let payload;
    try {
      payload = jwt.verify(token, env.JWT_SECRET, {
        algorithms: ['HS256'],
        issuer:    'upiguard-api',
        audience:  'upiguard-client',
      });
    } catch {
      return next(ApiError.unauthorized('Invalid or expired refresh token'));
    }

    if (payload.type !== 'refresh') {
      return next(ApiError.unauthorized('Not a refresh token'));
    }

    // Verify institution still active
    const { rows } = await db.query(
      `SELECT id, role, is_active FROM institutions WHERE id = $1 LIMIT 1`,
      [payload.sub]
    );

    if (!rows[0] || !rows[0].is_active) {
      return next(ApiError.unauthorized('Account no longer active'));
    }

    const { accessToken } = issueTokens(rows[0].id, rows[0].role);

    return res.json({ success: true, accessToken, expiresIn: env.JWT_ACCESS_EXPIRES_IN });
  } catch (err) {
    next(err);
  }
}

async function logout(req, res, next) {
  try {
    // Revoke current access token
    const payload = jwt.decode(
      req.headers.authorization?.slice(7)
    );
    if (payload?.jti && payload?.exp) {
      await revokeToken(payload.jti, payload.exp);
    }

    // Clear refresh cookie
    res.clearCookie('refreshToken', { path: '/api/v1/auth/refresh' });

    return res.json({ success: true, message: 'Logged out' });
  } catch (err) {
    next(err);
  }
}

module.exports = { register, login, refresh, logout };
