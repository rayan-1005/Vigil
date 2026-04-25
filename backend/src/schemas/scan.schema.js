// src/schemas/scan.schema.js
'use strict';

const { z } = require('zod');

const SUPPORTED_LANGUAGES = ['auto', 'en', 'hi', 'ta', 'te', 'bn', 'mr', 'gu', 'kn', 'ml', 'pa', 'ur', 'or', 'as'];
const SUPPORTED_SOURCES   = ['sms', 'whatsapp', 'upi_app', 'other'];

const scanSchema = z.object({
  // Cap message length to prevent DoS via enormous payloads to HF API
  message:  z.string().min(1, 'message is required').max(2000, 'message exceeds 2000 characters').trim(),
  language: z.enum(SUPPORTED_LANGUAGES).default('auto'),
  source:   z.enum(SUPPORTED_SOURCES).default('sms'),
});

const scanHistoryQuerySchema = z.object({
  page:      z.coerce.number().int().min(1).default(1),
  limit:     z.coerce.number().int().min(1).max(100).default(20),
  riskLevel: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
  from:      z.string().datetime({ offset: true }).optional(),
  to:        z.string().datetime({ offset: true }).optional(),
  language:  z.string().length(2).optional(),
});

module.exports = { scanSchema, scanHistoryQuerySchema };
