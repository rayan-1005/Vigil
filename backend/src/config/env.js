// src/config/env.js
// Validates ALL environment variables at startup.
// The process exits immediately if any required variable is missing or malformed.
// This prevents silent misconfigurations in production.

'use strict';

const { z } = require('zod');
require('dotenv').config();

const envSchema = z.object({
  // Server
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().int().min(1024).max(65535).default(3001),

  // Database – accept both postgres:// and postgresql:// (Neon uses either)
  DATABASE_URL: z.string().url().refine(
    (v) => v.startsWith('postgresql://') || v.startsWith('postgres://'),
    { message: 'DATABASE_URL must start with postgresql:// or postgres://' }
  ),

  // Redis
  REDIS_URL: z.string().url(),

  // JWT – enforce minimum 64-char secret to prevent weak key attacks
  JWT_SECRET: z.string().min(64, 'JWT_SECRET must be at least 64 characters'),
  JWT_ACCESS_EXPIRES_IN: z.string().default('15m'),   // Short-lived access tokens
  JWT_REFRESH_EXPIRES_IN: z.string().default('7d'),   // Refresh tokens

  // Hugging Face
  HF_API_TOKEN: z.string().startsWith('hf_', 'HF_API_TOKEN must start with hf_'),
  HF_TIMEOUT_MS: z.coerce.number().int().min(1000).max(30000).default(5000),
  HF_RETRY_ATTEMPTS: z.coerce.number().int().min(0).max(3).default(1),

  // Security
  BCRYPT_ROUNDS: z.coerce.number().int().min(10).max(14).default(12),
  CORS_ORIGIN: z.string().default('http://localhost:5173'),
  API_KEY_SALT: z.string().min(32, 'API_KEY_SALT must be at least 32 characters'),

  // Rate limiting
  RATE_LIMIT_WINDOW_MS: z.coerce.number().int().default(60_000),
  RATE_LIMIT_PUBLIC_MAX: z.coerce.number().int().default(60),
  RATE_LIMIT_AUTH_MAX: z.coerce.number().int().default(300),

  // SSE stream token TTL (seconds) – very short-lived, single-use
  SSE_STREAM_TOKEN_TTL_S: z.coerce.number().int().min(10).max(120).default(30),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('❌  Invalid environment configuration:');
  console.error(parsed.error.flatten().fieldErrors);
  process.exit(1);
}

module.exports = parsed.data;
