// src/utils/apiError.js
'use strict';

class ApiError extends Error {
  constructor(statusCode, code, message, details = null) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    Error.captureStackTrace(this, this.constructor);
  }

  static badRequest(message, details)    { return new ApiError(400, 'BAD_REQUEST', message, details); }
  static unauthorized(message = 'Unauthorized') { return new ApiError(401, 'UNAUTHORIZED', message); }
  static forbidden(message = 'Forbidden')       { return new ApiError(403, 'FORBIDDEN', message); }
  static notFound(resource = 'Resource')        { return new ApiError(404, 'NOT_FOUND', `${resource} not found`); }
  static conflict(message)               { return new ApiError(409, 'CONFLICT', message); }
  static unprocessable(message, details) { return new ApiError(422, 'UNPROCESSABLE', message, details); }
  static tooManyRequests()               { return new ApiError(429, 'RATE_LIMITED', 'Too many requests'); }
  static serviceUnavailable(service)     { return new ApiError(503, `${service.toUpperCase()}_UNAVAILABLE`, `${service} is temporarily unavailable`); }
}

module.exports = ApiError;
