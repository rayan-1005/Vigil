// src/controllers/alerts.controller.js
// SECURITY FIX: The original spec used ?token=<jwt> in the SSE URL.
//   This is a known security anti-pattern – JWTs in query strings appear in:
//     • Server access logs
//     • Browser history
//     • CDN / proxy logs
//     • Referrer headers
//
//   Our fix: a dedicated /alerts/stream-token endpoint issues a short-lived
//   (30 s, single-use) opaque token stored in Redis. The client passes this
//   token to /alerts/stream, where it is consumed (deleted) immediately.

'use strict';

const db = require('../config/database');
const { issueStreamToken, consumeStreamToken, addClient, removeClient } = require('../services/sseManager');

/** POST /alerts/stream-token  – requires Bearer JWT */
async function getStreamToken(req, res, next) {
  try {
    const token = await issueStreamToken(req.user.id);
    return res.json({ success: true, streamToken: token });
  } catch (err) {
    next(err);
  }
}

/** GET /alerts/stream?streamToken=<token>  – NO long-lived JWT in URL */
async function sseStream(req, res, next) {
  try {
    const { streamToken } = req.query;
    const institutionId = await consumeStreamToken(streamToken);

    if (!institutionId) {
      return res.status(401).json({ success: false, code: 'UNAUTHORIZED', message: 'Invalid or expired stream token' });
    }

    // Set SSE headers
    res.setHeader('Content-Type',  'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection',    'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no'); // nginx: disable proxy buffering
    res.flushHeaders();

    addClient(institutionId, res);

    // Heartbeat every 30 s to keep connection alive through proxies
    const heartbeat = setInterval(() => {
      try {
        res.write(`event: heartbeat\ndata: ${JSON.stringify({ ts: new Date().toISOString() })}\n\n`);
      } catch {
        clearInterval(heartbeat);
      }
    }, 30_000);

    req.on('close', () => {
      clearInterval(heartbeat);
      removeClient(institutionId, res);
    });
  } catch (err) {
    next(err);
  }
}

/** GET /alerts – paginated alert history */
async function listAlerts(req, res, next) {
  try {
    const institutionId = req.user.id;
    const page  = parseInt(req.query.page  ?? 1);
    const limit = Math.min(parseInt(req.query.limit ?? 20), 100);
    const offset = (page - 1) * limit;

    const { rows } = await db.query(
      `SELECT id, risk_score AS "riskScore", risk_level AS "riskLevel",
              flags, delivered_at AS "deliveredAt", acknowledged_at AS "acknowledgedAt",
              created_at AS "createdAt"
       FROM alerts
       WHERE institution_id = $1
       ORDER BY created_at DESC
       LIMIT $2 OFFSET $3`,
      [institutionId, limit, offset]
    );

    return res.json({ success: true, data: rows });
  } catch (err) {
    next(err);
  }
}

/** PATCH /alerts/:alertId/acknowledge */
async function acknowledgeAlert(req, res, next) {
  try {
    const { alertId } = req.params;
    const institutionId = req.user.id;

    const { rowCount } = await db.query(
      `UPDATE alerts SET acknowledged_at = NOW()
       WHERE id = $1 AND institution_id = $2 AND acknowledged_at IS NULL`,
      [alertId, institutionId]
    );

    if (rowCount === 0) return res.status(404).json({ success: false, message: 'Alert not found or already acknowledged' });

    return res.json({ success: true, message: 'Alert acknowledged' });
  } catch (err) {
    next(err);
  }
}

module.exports = { getStreamToken, sseStream, listAlerts, acknowledgeAlert };
