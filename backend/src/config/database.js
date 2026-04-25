// src/config/database.js
// Centralised pg Pool – use parameterised queries everywhere.
// NEVER build SQL strings via string interpolation.

'use strict';

const { Pool } = require('pg');
const env = require('./env');
const logger = require('../utils/logger');

// Neon (and most cloud Postgres providers) require SSL in all environments.
// rejectUnauthorized is only enforced in production to allow self-signed certs locally.
const sslConfig = env.DATABASE_URL.includes('sslmode=require')
  ? { rejectUnauthorized: env.NODE_ENV === 'production' }
  : false;

const pool = new Pool({
  connectionString: env.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
  ssl: sslConfig,
});

pool.on('error', (err) => {
  logger.error('Unexpected PostgreSQL client error', { error: err.message });
});

/**
 * Verify the pool can reach the database.
 * Called once at startup – exits the process if the DB is unreachable.
 */
async function verifyConnection() {
  const client = await pool.connect();
  try {
    await client.query('SELECT 1');
    logger.info('PostgreSQL connection verified');
  } finally {
    client.release();
  }
}

/**
 * Thin wrapper for parameterised queries.
 * Usage: await db.query('SELECT * FROM institutions WHERE id = $1', [id])
 */
const db = {
  query:             (text, params) => pool.query(text, params),
  getClient:         () => pool.connect(),
  verifyConnection,
};

module.exports = db;
