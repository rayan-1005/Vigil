// src/schemas/auth.schema.js
'use strict';

const { z } = require('zod');

const PASSWORD_RULES = z
  .string()
  .min(8, 'Password must be at least 8 characters')
  .max(128, 'Password too long')
  .regex(/[A-Z]/, 'Password must contain an uppercase letter')
  .regex(/[a-z]/, 'Password must contain a lowercase letter')
  .regex(/[0-9]/, 'Password must contain a digit')
  .regex(/[^A-Za-z0-9]/, 'Password must contain a special character');

const registerSchema = z.object({
  name: z.string().min(2).max(200).trim(),
  email: z.string().email().max(200).toLowerCase().trim(),
  password: PASSWORD_RULES,
  role: z.enum(['institution', 'admin']).default('institution'),
});

const loginSchema = z.object({
  email: z.string().email().toLowerCase().trim(),
  password: z.string().min(1).max(128),
});

const refreshSchema = z.object({
  // Optional in body — may arrive via httpOnly cookie instead (preferred path)
  refreshToken: z.string().min(1).optional(),
});

module.exports = { registerSchema, loginSchema, refreshSchema };
