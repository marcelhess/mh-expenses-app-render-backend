import rateLimit from "express-rate-limit";
import { logger } from "../utils/logger.js";

/**
 * Rate limiting middleware configurations for different endpoint types
 */

// General API rate limiter - applies to all API endpoints
export const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // Limit each IP to 1000 requests per windowMs
  message: {
    success: false,
    error: "Too many requests from this IP, please try again later.",
    retryAfter: "15 minutes"
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  handler: (req, res) => {
    logger.warn(`Rate limit exceeded for IP: ${req.ip} on ${req.originalUrl}`);
    res.status(429).json({
      success: false,
      error: "Too many requests from this IP, please try again later.",
      retryAfter: "15 minutes"
    });
  },
  skip: (req) => {
    // Skip rate limiting for internal API calls or during tests
    const internalToken = req.headers['x-internal-token'];
    return internalToken === process.env.API_INTERNAL_TOKEN || process.env.NODE_ENV === 'test';
  }
});

// Strict rate limiter for authentication endpoints
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 authentication attempts per windowMs
  message: {
    success: false,
    error: "Too many authentication attempts from this IP, please try again after 15 minutes.",
    retryAfter: "15 minutes"
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`Auth rate limit exceeded for IP: ${req.ip} on ${req.originalUrl}`);
    res.status(429).json({
      success: false,
      error: "Too many authentication attempts from this IP, please try again after 15 minutes.",
      retryAfter: "15 minutes"
    });
  },
  skipSuccessfulRequests: true, // Don't count successful requests
  skipFailedRequests: false, // Count failed requests
  skip: (req) => {
    // Skip rate limiting during tests
    return process.env.NODE_ENV === 'test';
  }
});

// Password reset rate limiter - even stricter
export const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Limit each IP to 3 password reset attempts per hour
  message: {
    success: false,
    error: "Too many password reset attempts from this IP, please try again after 1 hour.",
    retryAfter: "1 hour"
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`Password reset rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      success: false,
      error: "Too many password reset attempts from this IP, please try again after 1 hour.",
      retryAfter: "1 hour"
    });
  },
  skip: (req) => {
    // Skip rate limiting during tests
    return process.env.NODE_ENV === 'test';
  }
});

// Registration rate limiter
export const registrationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // Limit each IP to 5 registration attempts per hour
  message: {
    success: false,
    error: "Too many registration attempts from this IP, please try again after 1 hour.",
    retryAfter: "1 hour"
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`Registration rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      success: false,
      error: "Too many registration attempts from this IP, please try again after 1 hour.",
      retryAfter: "1 hour"
    });
  },
  skip: (req) => {
    // Skip rate limiting during tests
    return process.env.NODE_ENV === 'test';
  }
});

// API endpoints that modify data (POST, PUT, DELETE)
export const modifyDataLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 modify requests per windowMs
  message: {
    success: false,
    error: "Too many data modification requests from this IP, please try again later.",
    retryAfter: "15 minutes"
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`Data modification rate limit exceeded for IP: ${req.ip} on ${req.originalUrl}`);
    res.status(429).json({
      success: false,
      error: "Too many data modification requests from this IP, please try again later.",
      retryAfter: "15 minutes"
    });
  },
  skip: (req) => {
    // Skip rate limiting for internal API calls
    const internalToken = req.headers['x-internal-token'];
    return internalToken === process.env.API_INTERNAL_TOKEN;
  }
});

// File upload/export rate limiter
export const fileOperationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // Limit each IP to 20 file operations per windowMs
  message: {
    success: false,
    error: "Too many file operation requests from this IP, please try again later.",
    retryAfter: "15 minutes"
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`File operation rate limit exceeded for IP: ${req.ip} on ${req.originalUrl}`);
    res.status(429).json({
      success: false,
      error: "Too many file operation requests from this IP, please try again later.",
      retryAfter: "15 minutes"
    });
  }
});

// Maps API rate limiter (for Google Maps integration)
export const mapsLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // Limit each IP to 200 maps requests per windowMs
  message: {
    success: false,
    error: "Too many maps API requests from this IP, please try again later.",
    retryAfter: "15 minutes"
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`Maps API rate limit exceeded for IP: ${req.ip} on ${req.originalUrl}`);
    res.status(429).json({
      success: false,
      error: "Too many maps API requests from this IP, please try again later.",
      retryAfter: "15 minutes"
    });
  }
});

// Create a factory function for custom rate limiters
export const createCustomLimiter = (options) => {
  return rateLimit({
    windowMs: options.windowMs || 15 * 60 * 1000,
    max: options.max || 100,
    message: options.message || {
      success: false,
      error: "Too many requests from this IP, please try again later."
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      logger.warn(`Custom rate limit exceeded for IP: ${req.ip} on ${req.originalUrl}`);
      res.status(429).json(options.message || {
        success: false,
        error: "Too many requests from this IP, please try again later."
      });
    },
    ...options
  });
};