// src/services/redisClient.js
'use strict';

const { Redis } = require('ioredis');
const env = require('../config/env');
const logger = require('../utils/logger');

const redis = new Redis(env.REDIS_URL, {
  maxRetriesPerRequest: 3,
  lazyConnect: false,
  // TLS for production Redis (e.g. Upstash, Redis Cloud)
  tls: env.REDIS_URL.startsWith('rediss://') ? {} : undefined,
});

redis.on('connect', () => logger.info('Redis connected'));
redis.on('error', (err) => logger.error('Redis error', { error: err.message }));

module.exports = redis;
