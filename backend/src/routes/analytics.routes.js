// src/routes/analytics.routes.js
'use strict';

const { Router } = require('express');
const { getSummary } = require('../controllers/analytics.controller');
const { requireAuth, requireRole } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimiter');

const router = Router();
router.use(requireAuth, authLimiter);
router.get('/summary', requireRole('institution', 'admin'), getSummary);

module.exports = router;
