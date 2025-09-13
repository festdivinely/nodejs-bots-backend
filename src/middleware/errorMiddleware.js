// backend/middleware/errorHandler.js
import { logger } from '../logger/logger.js';
import crypto from 'crypto'; // Ensure crypto is imported for randomUUID

// Custom Error Classes
export class AppError extends Error {
    constructor(message, statusCode = 500) {
        super(message);
        this.statusCode = statusCode;
        this.isOperational = true; // Mark as trusted/operational error
        Error.captureStackTrace(this, this.constructor);
    }
}

export class NotFoundError extends AppError {
    constructor(message = 'Resource not found') {
        super(message, 404);
    }
}

export class ValidationError extends AppError {
    constructor(message = 'Invalid input data') {
        super(message, 400);
    }
}

export class UnauthorizedError extends AppError {
    constructor(message = 'Unauthorized access') {
        super(message, 401);
    }
}

export class ForbiddenError extends AppError {
    constructor(message = 'Access forbidden') {
        super(message, 403);
    }
}

export class ConflictError extends AppError {
    constructor(message = 'Conflict occurred') {
        super(message, 409);
    }
}

// Enhanced Error Handler Middleware
const errorHandler = (err, req, res, next) => {
    // Step 1: Determine the status code
    let statusCode = err.statusCode || res.statusCode || 500;
    if (statusCode < 400) statusCode = 500;

    // Step 2: Handle specific error types
    let message = err.message || 'An unexpected error occurred';
    let details = {};

    if (err.name === 'ValidationError') { // Mongoose or Joi validation
        statusCode = 400;
        message = 'Validation failed';
        details = err.errors ? Object.values(err.errors).map(e => e.message) : [];
    } else if (err.name === 'CastError') { // Mongoose invalid ID
        statusCode = 400;
        message = `Invalid value for ${err.path}`;
    } else if (err.name === 'SyntaxError' && err.message.includes('JSON')) {
        statusCode = 400;
        message = 'Invalid JSON in request body';
    } else if (err.code === 11000) { // MongoDB duplicate key
        statusCode = 409;
        message = 'Duplicate value entered';
    } else if (err.name === 'TokenExpiredError' || err.name === 'JsonWebTokenError') {
        statusCode = 401;
        message = 'Invalid or expired token';
    }

    // Step 3: Log the error
    const errorId = crypto.randomUUID();
    logger.error(
        {
            errorId,
            message,
            stack: err.stack,
            statusCode,
            method: req.method,
            url: req.originalUrl,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            user: req.user ? req.user.id : 'unauthenticated',
            body: req.body,
            params: req.params,
            query: req.query,
        },
        `Error occurred: ${message}`
    );

    // Step 4: Prepare the response
    const isProduction = process.env.NODE_ENV === 'production';
    res.status(statusCode).json({
        success: false,
        errorId,
        message,
        ...(details && Object.keys(details).length > 0 ? { details } : {}),
        ...(!isProduction ? { stack: err.stack } : {}),
    });

    // Step 5: Handle untrusted errors
    if (!err.isOperational && isProduction) {
        // Optionally: process.exit(1); // Avoid in clustered apps
    }
};

export default errorHandler;