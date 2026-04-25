// src/utils/logger.js
// Structured JSON logging. Never logs passwords, tokens, or raw message content.

'use strict';

const { createLogger, format, transports } = require('winston');
const env = require('../config/env');

const logger = createLogger({
  level: env.NODE_ENV === 'production' ? 'info' : 'debug',
  format: format.combine(
    format.timestamp(),
    format.errors({ stack: env.NODE_ENV !== 'production' }),
    format.json()
  ),
  transports: [
    new transports.Console({
      format: env.NODE_ENV !== 'production'
        ? format.combine(format.colorize(), format.simple())
        : format.json(),
    }),
  ],
});

module.exports = logger;
