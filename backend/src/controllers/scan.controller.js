// src/controllers/scan.controller.js
// SECURITY: raw_message is stored in PostgreSQL – institutions consent to this on registration.
//           The Redis cache key is a SHA-256 hash of the message, not the plaintext.

'use strict';

const { v4: uuidv4 } = require('uuid');
const db = require('../config/database');
const redis = require('../services/redisClient');
const { runPipeline } = require('../services/mlPipeline');
const { enqueueAlert } = require('../services/alertWorker');
const { messageHash } = require('../utils/crypto');
const ApiError = require('../utils/apiError');
const logger = require('../utils/logger');

const CACHE_TTL_S = 86_400; // 24 hours
const PIPELINE_CACHE_VERSION = 'v2';

async function submitScan(req, res, next) {
  const { message, source } = req.body;
  const institutionId = req.user.id;

  try {
    // 1. Check cache
    const cacheKey = `scan:cache:${PIPELINE_CACHE_VERSION}:` + messageHash(message);
    const cached = await redis.get(cacheKey).catch(() => null);
    if (cached) {
      logger.debug('Cache hit', { cacheKey });
      return res.json({
        success: true,
        cached:  true,
        scanId:  'cache_' + cacheKey.slice(-8),
        result:  JSON.parse(cached),
      });
    }

    // 2. Run ML pipeline before opening a DB transaction
    let pipelineResult;
    try {
      pipelineResult = await runPipeline(message);
    } catch (err) {
      throw ApiError.serviceUnavailable('HF');
    }

    const {
      detectedLanguage, translatedMessage, riskScore, riskLevel,
      classification, confidence, explanation, flags,
      entities, patternMatches, hfLatencyMs,
    } = pipelineResult;

    // 3. Persist scan request + result atomically inside a transaction
    const scanId = uuidv4();
    let scanResultId;

    const client = await db.getClient();
    try {
      await client.query('BEGIN');

      await client.query(
        'INSERT INTO scan_requests (id, institution_id, raw_message, source, ip_address, user_agent, status)' +
        " VALUES ($1, $2, $3, $4, $5::inet, $6, 'processing')",
        [scanId, institutionId, message, source, req.ip, req.headers['user-agent']?.slice(0, 512)]
      );

      const { rows } = await client.query(
        'INSERT INTO scan_results' +
        '  (id, scan_request_id, detected_language, translated_message, risk_score,' +
        '   risk_level, classification, confidence, explanation, flags, entities,' +
        '   pattern_matches, hf_latency_ms)' +
        ' VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)' +
        ' RETURNING id, created_at',
        [
          scanId, detectedLanguage, translatedMessage, riskScore,
          riskLevel, classification, confidence, explanation,
          flags, JSON.stringify(entities), JSON.stringify(patternMatches), hfLatencyMs,
        ]
      );
      scanResultId = rows[0].id;

      await client.query("UPDATE scan_requests SET status = 'done' WHERE id = $1", [scanId]);

      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }

    // 4. Cache result
    const resultPayload = {
      riskScore, riskLevel, classification, confidence,
      detectedLanguage, explanation, flags, entities, patternMatches,
    };
    await redis.setex(cacheKey, CACHE_TTL_S, JSON.stringify(resultPayload)).catch(() => null);

    // 5. Enqueue alert if high risk
    if (riskScore >= 70) {
      await enqueueAlert({ institutionId, scanResultId, riskScore, riskLevel, flags });
    }

    return res.json({
      success:   true,
      cached:    false,
      scanId,
      timestamp: new Date().toISOString(),
      result:    resultPayload,
    });
  } catch (err) {
    next(err);
  }
}

async function getScanHistory(req, res, next) {
  try {
    const { page, limit, riskLevel, from, to, language } = req.query;
    const offset = (page - 1) * limit;
    const institutionId = req.user.id;

    // Build parameterised WHERE clause – never interpolate values directly into SQL
    const conditions = ['sr.institution_id = $1'];
    const params = [institutionId];
    let pi = 2;

    if (riskLevel) { conditions.push('res.risk_level = $' + pi++); params.push(riskLevel); }
    if (from)      { conditions.push('sr.created_at >= $' + pi++); params.push(from); }
    if (to)        { conditions.push('sr.created_at <= $' + pi++); params.push(to); }
    if (language)  { conditions.push('res.detected_language = $' + pi++); params.push(language); }

    const whereClause = conditions.join(' AND ');
    // pi now points to the next available placeholder index
    const limitIdx  = pi;
    const offsetIdx = pi + 1;

    const [dataResult, countResult] = await Promise.all([
      db.query(
        'SELECT sr.id AS "scanId", res.risk_score AS "riskScore", res.risk_level AS "riskLevel",' +
        ' res.classification, res.detected_language AS "detectedLanguage",' +
        ' sr.source, sr.created_at AS "createdAt"' +
        ' FROM scan_requests sr' +
        ' JOIN scan_results res ON res.scan_request_id = sr.id' +
        ' WHERE ' + whereClause +
        ' ORDER BY sr.created_at DESC' +
        ' LIMIT $' + limitIdx + ' OFFSET $' + offsetIdx,
        [...params, limit, offset]
      ),
      db.query(
        'SELECT COUNT(*) FROM scan_requests sr' +
        ' JOIN scan_results res ON res.scan_request_id = sr.id' +
        ' WHERE ' + whereClause,
        params
      ),
    ]);

    return res.json({
      success:    true,
      pagination: { page, limit, total: parseInt(countResult.rows[0].count) },
      data:       dataResult.rows,
    });
  } catch (err) {
    next(err);
  }
}

async function getScanById(req, res, next) {
  try {
    const { scanId } = req.params;
    const institutionId = req.user.id;

    const { rows } = await db.query(
      'SELECT sr.id AS "scanId", res.risk_score AS "riskScore", res.risk_level AS "riskLevel",' +
      ' res.classification, res.confidence, res.detected_language AS "detectedLanguage",' +
      ' res.explanation, res.flags, res.entities, res.pattern_matches AS "patternMatches",' +
      ' sr.source, sr.created_at AS "createdAt"' +
      ' FROM scan_requests sr' +
      ' JOIN scan_results res ON res.scan_request_id = sr.id' +
      ' WHERE sr.id = $1 AND sr.institution_id = $2' +
      ' LIMIT 1',
      [scanId, institutionId]
    );

    if (!rows[0]) return next(ApiError.notFound('Scan'));

    return res.json({ success: true, data: rows[0] });
  } catch (err) {
    next(err);
  }
}

module.exports = { submitScan, getScanHistory, getScanById };
