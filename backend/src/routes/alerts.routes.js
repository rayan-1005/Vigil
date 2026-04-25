// src/routes/alerts.routes.js
'use strict';

const { Router } = require('express');
const { getStreamToken, sseStream, listAlerts, acknowledgeAlert } = require('../controllers/alerts.controller');
const { requireAuth } = require('../middleware/auth');
const { authLimiter, publicLimiter } = require('../middleware/rateLimiter');

const router = Router();

router.post('/stream-token', requireAuth, authLimiter, getStreamToken);
router.get('/stream',        publicLimiter, sseStream);              // token in query, not JWT
router.get('/',              requireAuth, authLimiter, listAlerts);
router.patch('/:alertId/acknowledge', requireAuth, authLimiter, acknowledgeAlert);

module.exports = router;
