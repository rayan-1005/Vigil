// src/controllers/health.controller.js
'use strict';

const db = require('../config/database');
const redis = require('../services/redisClient');

async function liveness(_req, res) {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
}

async function deepCheck(req, res, next) {
  try {
    const checks = {};

    // DB
    try {
      await db.query('SELECT 1');
      checks.database = 'ok';
    } catch { checks.database = 'error'; }

    // Redis
    try {
      await redis.ping();
      checks.redis = 'ok';
    } catch { checks.redis = 'error'; }

    // HF API (use cached status, don't make live calls on health check)
    try {
      const hfStatus = await redis.get('hf:status').catch(() => null);
      checks.hf = hfStatus ? JSON.parse(hfStatus) : 'unknown';
    } catch {
      checks.hf = 'unknown';
    }

    const allOk = Object.values(checks).every(v => v === 'ok' || typeof v === 'object');

    return res.status(allOk ? 200 : 503).json({ status: allOk ? 'ok' : 'degraded', checks });
  } catch (err) {
    next(err);
  }
}

module.exports = { liveness, deepCheck };
