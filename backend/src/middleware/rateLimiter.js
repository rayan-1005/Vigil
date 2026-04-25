// src/middleware/rateLimiter.js
// Sliding-window rate limiters backed by Redis.
// SECURITY FIX: The original spec only mentioned rate-limiting at a high level.
//               Here we wire up actual Redis-backed limiters per route class.

'use strict';

const rateLimit = require('express-rate-limit');
const { RedisStore } = require('rate-limit-redis');
const redis = require('../services/redisClient');
const env = require('../config/env');

function makeStore(prefix) {
  return new RedisStore({
    sendCommand: (...args) => redis.call(...args),
    prefix,
  });
}

/** For unauthenticated / public endpoints (60 req/min) */
const publicLimiter = rateLimit({
  windowMs:         env.RATE_LIMIT_WINDOW_MS,
  max:              env.RATE_LIMIT_PUBLIC_MAX,
  standardHeaders:  true,
  legacyHeaders:    false,
  store:            makeStore('rl:pub:'),
  keyGenerator:     (req) => req.ip,
  handler:          (_req, res) =>
    res.status(429).json({ success: false, code: 'RATE_LIMITED', message: 'Too many requests' }),
});

/** For authenticated institution endpoints (300 req/min) */
const authLimiter = rateLimit({
  windowMs:         env.RATE_LIMIT_WINDOW_MS,
  max:              env.RATE_LIMIT_AUTH_MAX,
  standardHeaders:  true,
  legacyHeaders:    false,
  store:            makeStore('rl:auth:'),
  // Key on institution ID so different IPs with same token share the quota
  keyGenerator:     (req) => req.user?.id ?? req.ip,
  handler:          (_req, res) =>
    res.status(429).json({ success: false, code: 'RATE_LIMITED', message: 'Too many requests' }),
});

/** Strict limiter for auth endpoints to slow brute-force */
const authEndpointLimiter = rateLimit({
  windowMs:         15 * 60 * 1000, // 15 min
  max:              10,
  standardHeaders:  true,
  legacyHeaders:    false,
  store:            makeStore('rl:login:'),
  keyGenerator:     (req) => req.ip,
  handler:          (_req, res) =>
    res.status(429).json({ success: false, code: 'RATE_LIMITED', message: 'Too many login attempts. Try again in 15 minutes.' }),
});

module.exports = { publicLimiter, authLimiter, authEndpointLimiter };
