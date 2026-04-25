// src/server.js
'use strict';

const app = require('./app.js');
const env = require('./config/env.js');
const db  = require('./config/database.js');
const logger = require('./utils/logger.js');

// Initialise alert worker (registers BullMQ worker)
require('./services/alertWorker.js');

async function start() {
  // Verify database connectivity before accepting traffic
  try {
    await db.verifyConnection();
  } catch (err) {
    logger.error('Failed to connect to PostgreSQL – aborting startup', { error: err.message });
    process.exit(1);
  }

  const server = app.listen(env.PORT, () => {
    logger.info('UPI Fraud Guard API running', { port: env.PORT, env: env.NODE_ENV });
    console.log(`UPI Fraud Guard API running on port ${env.PORT} (${env.NODE_ENV})`);
  });

  // Graceful shutdown
  function shutdown(signal) {
    logger.info(`${signal} received – shutting down`);
    server.close(() => {
      logger.info('HTTP server closed');
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10_000);
  }

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));
}

process.on('uncaughtException', (err) => {
  logger.error('Uncaught exception', { error: err.message, stack: err.stack });
  process.exit(1);
});
process.on('unhandledRejection', (err) => {
  logger.error('Unhandled rejection', { error: err?.message });
  process.exit(1);
});

start();
