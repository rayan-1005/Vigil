// src/utils/crypto.js
// Provides deterministic and non-deterministic crypto helpers.
// API keys are hashed with HMAC-SHA256 before storage –
// only the hash lives in the database, never the plaintext.

'use strict';

const crypto = require('crypto');
const env = require('../config/env');

/**
 * Generate a cryptographically secure random API key (hex, 32 bytes → 64 chars).
 * Returned to the caller ONCE; only the HMAC hash is stored.
 */
function generateApiKey() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * HMAC-SHA256 of the API key using the server-side salt.
 * Deterministic: same input → same hash.
 */
function hashApiKey(plainKey) {
  return crypto
    .createHmac('sha256', env.API_KEY_SALT)
    .update(plainKey)
    .digest('hex');
}

/**
 * SHA-256 of a message for Redis cache keying.
 * Not used for security – just for stable, fixed-length cache keys.
 */
function messageHash(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

/**
 * Constant-time comparison to prevent timing attacks on token comparisons.
 */
function safeEqual(a, b) {
  try {
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch {
    return false;
  }
}

module.exports = { generateApiKey, hashApiKey, messageHash, safeEqual };
