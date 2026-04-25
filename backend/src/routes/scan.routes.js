// src/routes/scan.routes.js
'use strict';

const { Router } = require('express');
const { submitScan, getScanHistory, getScanById } = require('../controllers/scan.controller');
const { requireAuth } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimiter');
const validate = require('../middleware/validate');
const { scanSchema, scanHistoryQuerySchema } = require('../schemas/scan.schema');

const router = Router();

router.use(requireAuth, authLimiter);

router.post('/',       validate(scanSchema),              submitScan);
router.get('/',        validate(scanHistoryQuerySchema, 'query'), getScanHistory);
router.get('/:scanId', getScanById);

module.exports = router;
