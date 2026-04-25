// src/routes/health.routes.js
'use strict';

const { Router } = require('express');
const { liveness, deepCheck } = require('../controllers/health.controller');
const { requireAuth, requireRole } = require('../middleware/auth');
const { publicLimiter } = require('../middleware/rateLimiter');

const router = Router();
router.get('/',      publicLimiter, liveness);
router.get('/deep',  requireAuth, requireRole('admin'), deepCheck);

module.exports = router;
