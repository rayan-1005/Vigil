// src/middleware/auth.js
// Verifies JWT access tokens and checks the Redis revocation list (logout support).
// SECURITY: We store the token's `jti` in Redis on logout.
//           On every request we check the jti is not revoked before allowing access.

'use strict';

const jwt = require('jsonwebtoken');
const redis = require('../services/redisClient');
const env = require('../config/env');
const ApiError = require('../utils/apiError');

/**
 * Middleware: validate Bearer JWT, attach decoded payload to req.user.
 */
async function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next(ApiError.unauthorized('Missing or malformed Authorization header'));
    }

    const token = authHeader.slice(7);

    let payload;
    try {
      payload = jwt.verify(token, env.JWT_SECRET, {
        algorithms: ['HS256'],
        issuer:     'upiguard-api',
        audience:   'upiguard-client',
      });
    } catch (err) {
      return next(ApiError.unauthorized('Invalid or expired token'));
    }

    // Check revocation list
    const revoked = await redis.get(`revoked:${payload.jti}`);
    if (revoked) {
      return next(ApiError.unauthorized('Token has been revoked'));
    }

    req.user = {
      id:   payload.sub,
      role: payload.role,
      jti:  payload.jti,
    };

    next();
  } catch (err) {
    next(err);
  }
}

/**
 * Middleware factory: restrict access to specific roles.
 */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return next(ApiError.forbidden('Insufficient permissions'));
    }
    next();
  };
}

/**
 * Issue a short-lived access token + long-lived refresh token.
 */
const { v4: uuidv4 } = require('uuid');

function issueTokens(institutionId, role) {
  const jti = uuidv4();

  const accessToken = jwt.sign(
    { sub: institutionId, role, jti },
    env.JWT_SECRET,
    {
      algorithm: 'HS256',
      expiresIn:  env.JWT_ACCESS_EXPIRES_IN,
      issuer:    'upiguard-api',
      audience:  'upiguard-client',
    }
  );

  const refreshToken = jwt.sign(
    { sub: institutionId, role, type: 'refresh' },
    env.JWT_SECRET,
    {
      algorithm: 'HS256',
      expiresIn:  env.JWT_REFRESH_EXPIRES_IN,
      issuer:    'upiguard-api',
      audience:  'upiguard-client',
    }
  );

  return { accessToken, refreshToken, jti };
}

/**
 * Revoke an access token by adding its jti to Redis until it expires.
 * TTL is set to the token's remaining lifetime to avoid unbounded growth.
 */
async function revokeToken(jti, expiresAt) {
  const ttl = Math.max(expiresAt - Math.floor(Date.now() / 1000), 1);
  await redis.setex(`revoked:${jti}`, ttl, '1');
}

module.exports = { requireAuth, requireRole, issueTokens, revokeToken };
