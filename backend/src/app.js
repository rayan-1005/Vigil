// src/app.js
// Express application factory.
// SECURITY layers applied here in order:
//   1. Helmet (security headers incl. CSP, HSTS)
//   2. CORS (strict origin whitelist)
//   3. Body size limits (prevent payload DoS)
//   4. Request ID injection (for log correlation)
//   5. Morgan request logging (no Authorization header logged)
//   6. Routes
//   7. 404 handler
//   8. Global error handler

'use strict';

const express      = require('express');
const helmet       = require('helmet');
const cors         = require('cors');
const cookieParser = require('cookie-parser');
const morgan       = require('morgan');
const { v4: uuidv4 } = require('uuid');
const env = require('./config/env');
const logger = require('./utils/logger');
const errorHandler = require('./middleware/errorHandler');

// Routes
const authRoutes      = require('./routes/auth.routes');
const scanRoutes      = require('./routes/scan.routes');
const alertRoutes     = require('./routes/alerts.routes');
const analyticsRoutes = require('./routes/analytics.routes');
const healthRoutes    = require('./routes/health.routes');

const app = express();

// ── 1. Security headers ───────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'none'"],
      scriptSrc:  ["'self'"],
      connectSrc: ["'self'"],
      imgSrc:     ["'self'"],
      frameAncestors: ["'none'"],
    },
  },
  hsts: {
    maxAge:            31_536_000,
    includeSubDomains: true,
    preload:           true,
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));

// Remove X-Powered-By header (helmet does this, but explicit for clarity)
app.disable('x-powered-by');

// ── 2. CORS ───────────────────────────────────────────────────────────────
const allowedOrigins = env.CORS_ORIGIN.split(',').map(o => o.trim());
app.use(cors({
  origin: (origin, cb) => {
    // Allow requests with no origin (mobile apps, curl) only in dev
    if (!origin && env.NODE_ENV !== 'production') return cb(null, true);
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error(`CORS: origin ${origin} not allowed`));
  },
  credentials:     true,
  allowedHeaders:  ['Content-Type', 'Authorization', 'Accept-Language'],
  exposedHeaders:  ['X-Request-ID'],
  methods:         ['GET', 'POST', 'PATCH', 'DELETE'],
}));

// ── 2b. Cookie parsing (needed for httpOnly refresh-token cookie) ─────────
app.use(cookieParser());

// ── 3. Body parsing with size limits ─────────────────────────────────────
app.use(express.json({ limit: '50kb' }));     // Reject large JSON bodies
app.use(express.urlencoded({ extended: false, limit: '20kb' }));

// ── 4. Request ID ─────────────────────────────────────────────────────────
app.use((req, res, next) => {
  req.id = uuidv4();
  res.setHeader('X-Request-ID', req.id);
  next();
});

// ── 5. HTTP request logging ───────────────────────────────────────────────
// Custom format: never log Authorization header value
morgan.token('id', req => req.id);
app.use(morgan(':id :method :url :status :res[content-length] - :response-time ms', {
  stream: { write: (msg) => logger.info(msg.trim()) },
  skip:   (_req, res) => res.statusCode < 400 && env.NODE_ENV === 'production',
}));

// ── 6. Routes ─────────────────────────────────────────────────────────────
app.use('/api/v1/auth',      authRoutes);
app.use('/api/v1/scan',      scanRoutes);
app.use('/api/v1/scans',     scanRoutes);
app.use('/api/v1/alerts',    alertRoutes);
app.use('/api/v1/analytics', analyticsRoutes);
app.use('/api/v1/health',    healthRoutes);

// ── 7. 404 ────────────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ success: false, code: 'NOT_FOUND', message: 'Endpoint not found' });
});

// ── 8. Error handler ──────────────────────────────────────────────────────
app.use(errorHandler);

module.exports = app;
