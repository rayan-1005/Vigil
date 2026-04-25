// src/services/alertWorker.js
// BullMQ worker: processes high-risk scan events and pushes to SSE clients.

"use strict";

const { Worker, Queue } = require("bullmq");
const { Redis: IORedis } = require("ioredis");
const env = require("../config/env");
const db = require("../config/database");
const sseManager = require("./sseManager");
const logger = require("../utils/logger");

// BullMQ requires its own Redis connection
const connection = new IORedis(env.REDIS_URL, {
  maxRetriesPerRequest: null, // required by BullMQ
  tls: env.REDIS_URL.startsWith("rediss://") ? {} : undefined,
});

const ALERT_QUEUE = "alert-queue";

const alertQueue = new Queue(ALERT_QUEUE, { connection });

const worker = new Worker(
  ALERT_QUEUE,
  async (job) => {
    const { institutionId, scanResultId, riskScore, riskLevel, flags } =
      job.data;

    // Persist alert to DB
    const { rows } = await db.query(
      `INSERT INTO alerts (id, scan_result_id, institution_id, risk_score, risk_level, flags)
       VALUES (gen_random_uuid(), $1, $2, $3, $4, $5)
       RETURNING id, created_at`,
      [scanResultId, institutionId, riskScore, riskLevel, flags],
    );

    const alert = rows[0];

    // Mark delivered
    await db.query(`UPDATE alerts SET delivered_at = NOW() WHERE id = $1`, [
      alert.id,
    ]);

    // Push to any live SSE connections
    sseManager.pushAlert(institutionId, {
      alertId: alert.id,
      riskScore,
      riskLevel,
      flags,
      timestamp: alert.created_at,
    });

    logger.info("Alert dispatched", {
      alertId: alert.id,
      institutionId,
      riskLevel,
    });
  },
  { connection, concurrency: 5 },
);

worker.on("failed", (job, err) => {
  logger.error("Alert job failed", { jobId: job?.id, error: err.message });
});

/**
 * Enqueue an alert for a high-risk scan.
 */
async function enqueueAlert(payload) {
  await alertQueue.add("fraud_alert", payload, {
    attempts: 3,
    backoff: { type: "exponential", delay: 2000 },
    removeOnComplete: 100,
    removeOnFail: 50,
  });
}

module.exports = { enqueueAlert };
