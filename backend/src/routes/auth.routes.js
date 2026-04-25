// src/routes/auth.routes.js
'use strict';

const { Router } = require('express');
const { register, login, refresh, logout } = require('../controllers/auth.controller');
const { requireAuth } = require('../middleware/auth');
const validate = require('../middleware/validate');
const { authEndpointLimiter } = require('../middleware/rateLimiter');
const { registerSchema, loginSchema, refreshSchema } = require('../schemas/auth.schema');

const router = Router();

router.post('/register', authEndpointLimiter, validate(registerSchema), register);
router.post('/login',    authEndpointLimiter, validate(loginSchema),    login);
router.post('/refresh',                       validate(refreshSchema),  refresh);
router.post('/logout',   requireAuth,                                   logout);

module.exports = router;
