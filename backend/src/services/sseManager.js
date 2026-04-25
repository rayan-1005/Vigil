// src/services/sseManager.js
// Manages Server-Sent Event connections per institution.
// SECURITY: We do NOT accept JWT in query params (they get logged in access logs,
//           browser history, and CDN/proxy logs). Instead, a short-lived
//           single-use stream token is issued from a separate endpoint and
//           consumed here.

'use strict';

const redis = require('./redisClient');
const env = require('../config/env');
const crypto = require('crypto');
const logger = require('../utils/logger');

/** institution_id → Set<res> */
const connections = new Map();

/** Register an SSE response object for an institution. */
function addClient(institutionId, res) {
  if (!connections.has(institutionId)) {
    connections.set(institutionId, new Set());
  }
  connections.get(institutionId).add(res);
  logger.debug('SSE client added', { institutionId, total: connections.get(institutionId).size });
}

/** Remove a disconnected client. */
function removeClient(institutionId, res) {
  connections.get(institutionId)?.delete(res);
  if (connections.get(institutionId)?.size === 0) {
    connections.delete(institutionId);
  }
}

/** Push a fraud_alert event to all connected clients of an institution. */
function pushAlert(institutionId, payload) {
  const clients = connections.get(institutionId);
  if (!clients || clients.size === 0) return;

  const data = JSON.stringify(payload);
  for (const res of clients) {
    try {
      res.write(`event: fraud_alert\ndata: ${data}\n\n`);
    } catch (err) {
      logger.warn('SSE write failed', { error: err.message });
      removeClient(institutionId, res);
    }
  }
}

/** Issue a short-lived single-use stream token stored in Redis. */
async function issueStreamToken(institutionId) {
  const token = crypto.randomBytes(24).toString('hex');
  await redis.setex(
    `sse:token:${token}`,
    env.SSE_STREAM_TOKEN_TTL_S,
    institutionId
  );
  return token;
}

/**
 * Consume a stream token – returns institutionId or null.
 * Deletes the token immediately (single-use).
 */
async function consumeStreamToken(token) {
  if (!token || typeof token !== 'string' || token.length !== 48) return null;
  const institutionId = await redis.getdel(`sse:token:${token}`);
  return institutionId ?? null;
}

module.exports = { addClient, removeClient, pushAlert, issueStreamToken, consumeStreamToken };
