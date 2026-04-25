// src/middleware/errorHandler.js
// Centralised error handler.
// SECURITY: stack traces are NEVER sent to clients in production.

'use strict';

const ApiError = require('../utils/apiError');
const logger = require('../utils/logger');
const env = require('../config/env');

// PostgreSQL error code → HTTP response map
const PG_ERROR_MAP = {
  '23505': { status: 409, code: 'CONFLICT',             message: 'A record with this value already exists' },
  '23503': { status: 409, code: 'FOREIGN_KEY_VIOLATION', message: 'Referenced record does not exist' },
  '23502': { status: 400, code: 'NOT_NULL_VIOLATION',    message: 'A required field is missing' },
  '23514': { status: 400, code: 'CHECK_VIOLATION',       message: 'A value failed a database constraint' },
  '40001': { status: 503, code: 'SERIALIZATION_FAILURE', message: 'Transaction conflict – please retry' },
  '40P01': { status: 503, code: 'DEADLOCK_DETECTED',     message: 'Deadlock detected – please retry' },
  '57014': { status: 504, code: 'QUERY_TIMEOUT',         message: 'Database query timed out' },
  '08006': { status: 503, code: 'DB_CONNECTION_FAILURE', message: 'Database connection failed' },
  '08001': { status: 503, code: 'DB_CONNECTION_FAILURE', message: 'Unable to connect to database' },
  '08004': { status: 503, code: 'DB_CONNECTION_FAILURE', message: 'Database connection rejected' },
};

// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, _next) {
  const requestId = req.id;

  // Log the full error internally
  logger.error('Request error', {
    requestId,
    method:  req.method,
    path:    req.path,
    error:   err.message,
    pgCode:  err.code,
    stack:   env.NODE_ENV !== 'production' ? err.stack : undefined,
  });

  if (err instanceof ApiError) {
    return res.status(err.statusCode).json({
      success: false,
      code:    err.code,
      message: err.message,
      ...(err.details && { details: err.details }),
      requestId,
    });
  }

  // Mapped PostgreSQL errors
  const pgError = PG_ERROR_MAP[err.code];
  if (pgError) {
    return res.status(pgError.status).json({
      success: false,
      code:    pgError.code,
      message: pgError.message,
      requestId,
    });
  }

  // Default: 500 – never expose internal details
  return res.status(500).json({
    success: false,
    code:    'INTERNAL_ERROR',
    message: 'An unexpected error occurred',
    requestId,
  });
}

module.exports = errorHandler;
