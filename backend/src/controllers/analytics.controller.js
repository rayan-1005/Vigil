// src/controllers/analytics.controller.js
'use strict';

const db = require('../config/database');

async function getSummary(req, res, next) {
  try {
    const institutionId = req.user.id;

    const { rows } = await db.query(
      `SELECT
         COUNT(*)                                                      AS "totalScans",
         COUNT(*) FILTER (WHERE res.classification = 'FRAUDULENT')    AS "fraudulent",
         COUNT(*) FILTER (WHERE res.classification = 'SUSPICIOUS')    AS "suspicious",
         COUNT(*) FILTER (WHERE res.classification = 'LEGITIMATE')    AS "legitimate",
         ROUND(AVG(res.risk_score), 1)                                AS "riskScoreAvg",
         COUNT(a.id)                                                   AS "alertsTriggered"
       FROM scan_requests sr
       JOIN scan_results res ON res.scan_request_id = sr.id
       LEFT JOIN alerts a ON a.scan_result_id = res.id
       WHERE sr.institution_id = $1
         AND sr.created_at >= NOW() - INTERVAL '30 days'`,
      [institutionId]
    );

    // Top scam types
    const { rows: topScam } = await db.query(
      `SELECT unnest(res.flags) AS flag, COUNT(*) AS cnt
       FROM scan_requests sr
       JOIN scan_results res ON res.scan_request_id = sr.id
       WHERE sr.institution_id = $1
         AND sr.created_at >= NOW() - INTERVAL '30 days'
       GROUP BY flag ORDER BY cnt DESC LIMIT 5`,
      [institutionId]
    );

    // Top languages
    const { rows: topLang } = await db.query(
      `SELECT res.detected_language AS lang, COUNT(*) AS cnt
       FROM scan_requests sr
       JOIN scan_results res ON res.scan_request_id = sr.id
       WHERE sr.institution_id = $1
         AND sr.created_at >= NOW() - INTERVAL '30 days'
       GROUP BY lang ORDER BY cnt DESC LIMIT 5`,
      [institutionId]
    );

    return res.json({
      success: true,
      period:  'last_30_days',
      data: {
        ...rows[0],
        topScamTypes: topScam.map(r => ({ flag: r.flag, count: parseInt(r.cnt) })),
        topLanguages: topLang.map(r => ({ language: r.lang, count: parseInt(r.cnt) })),
      },
    });
  } catch (err) {
    next(err);
  }
}

module.exports = { getSummary };
