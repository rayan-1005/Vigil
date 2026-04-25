// src/middleware/validate.js
// Factory middleware: validates req.body (or req.query) against a Zod schema.
// Returns 400 with structured field errors on failure.

"use strict";

const { ZodError } = require("zod");

/**
 * @param {import('zod').ZodSchema} schema
 * @param {'body'|'query'|'params'} source
 */
function validate(schema, source = "body") {
  return (req, res, next) => {
    const result = schema.safeParse(req[source]);
    if (!result.success) {
      const errors = result.error.flatten().fieldErrors;
      return res.status(400).json({
        success: false,
        code: "INVALID_INPUT",
        message: "Request validation failed",
        errors,
      });
    }
    // Replace the source with the coerced, trimmed data
    if (source === "body") {
      req.body = result.data;
    } else {
      // For query and params, mutate in place (cannot reassign)
      Object.keys(req[source]).forEach((key) => {
        delete req[source][key];
      });
      Object.assign(req[source], result.data);
    }
    next();
  };
}

module.exports = validate;
