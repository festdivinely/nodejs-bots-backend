import { Router } from "express";
import rateLimit from "express-rate-limit";
import {
    login,
    register,
    logout,
    requestPasswordReset,
    resetPassword,
    verifyEmail,
    resendVerifyEmail,
    resendVerifyDevice,
    refreshToken,
    updateProfileImage,
    updateUsername,
    getProfile,
    getAdminDashboard,
    verifyDevice,
} from "../controllers/authController.js";
import { protect, requireRole, csrfProtect } from "../middleware/authMiddleware.js";
import { logger, httpLogger } from "../logger/logger.js";
import requestIp from "request-ip";

const router = Router();

logger.info('Initializing auth routes', { route: '/api/auth', timestamp: new Date().toISOString() });

const registerLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 5,
    message: 'Too many registration attempts, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        logger.warn('Rate limit exceeded for register', {
            ip: requestIp.getClientIp(req),
            path: req.originalUrl,
        });
        res.status(429).json({ message: 'Too many registration attempts, please try again later' });
    },
});

const loginLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 10,
    message: 'Too many login attempts, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        logger.warn('Rate limit exceeded for login', {
            ip: requestIp.getClientIp(req),
            path: req.originalUrl,
        });
        res.status(429).json({ message: 'Too many login attempts, please try again later' });
    },
});

const verifyDeviceLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 3,
    message: 'Too many OTP attempts, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        logger.warn('Rate limit exceeded for verify-device', {
            ip: requestIp.getClientIp(req),
            path: req.originalUrl,
        });
        res.status(429).json({ message: 'Too many OTP attempts, please try again later' });
    },
});

const resendVerifyDeviceLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 3,
    message: 'Too many resend device verification attempts, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        logger.warn('Rate limit exceeded for resend-verify-device', {
            ip: requestIp.getClientIp(req),
            path: req.originalUrl,
        });
        res.status(429).json({ message: 'Too many resend device verification attempts, please try again later' });
    },
});

const resetLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 3,
    message: 'Too many password reset requests, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        logger.warn('Rate limit exceeded for reset-password', {
            ip: requestIp.getClientIp(req),
            path: req.originalUrl,
        });
        res.status(429).json({ message: 'Too many password reset requests, please try again later' });
    },
});

const refreshLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 10,
    message: 'Too many refresh attempts, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        logger.warn('Rate limit exceeded for refresh-token', {
            ip: requestIp.getClientIp(req),
            path: req.originalUrl,
        });
        res.status(429).json({ message: 'Too many refresh attempts, please try again later' });
    },
});

const verifyLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 5,
    message: 'Too many verification attempts, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        logger.warn('Rate limit exceeded for verify-email', {
            ip: requestIp.getClientIp(req),
            path: req.originalUrl,
        });
        res.status(429).json({ message: 'Too many verification attempts, please try again later' });
    },
});

const resendVerifyEmailLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 3,
    message: 'Too many resend verification email attempts, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        logger.warn('Rate limit exceeded for resend-verify-email', {
            ip: requestIp.getClientIp(req),
            path: req.originalUrl,
        });
        res.status(429).json({ message: 'Too many resend verification email attempts, please try again later' });
    },
});

const logRequest = (req, res, next) => {
    logger.info(`${req.method} ${req.originalUrl} route accessed`, {
        method: req.method,
        path: req.originalUrl,
        ip: requestIp.getClientIp(req),
        userAgent: req.headers['user-agent'],
        body: { ...req.body, password: req.body.password ? '[REDACTED]' : undefined, totp: req.body.totp ? '[REDACTED]' : undefined, otp: req.body.otp ? '[REDACTED]' : undefined },
        timestamp: new Date().toISOString(),
    });
    next();
};

router.post('/register', httpLogger, logRequest, registerLimiter, register);
router.post('/login', httpLogger, logRequest, loginLimiter, login);
router.post('/verify-device', httpLogger, logRequest, verifyDeviceLimiter, verifyDevice);
router.post('/resend-verify-device', httpLogger, logRequest, resendVerifyDeviceLimiter, resendVerifyDevice);
router.post('/logout', httpLogger, logRequest, protect, csrfProtect, logout);
router.post('/request-password-reset', httpLogger, logRequest, resetLimiter, requestPasswordReset);
router.post('/reset-password/:token', httpLogger, logRequest, resetLimiter, resetPassword);
router.post('/verify-email', httpLogger, logRequest, verifyLimiter, verifyEmail);
router.post('/resend-verify-email', httpLogger, logRequest, resendVerifyEmailLimiter, resendVerifyEmail);
router.post('/refresh-token', httpLogger, logRequest, refreshLimiter, refreshToken);
router.get('/profile', httpLogger, logRequest, protect, getProfile);
router.get('/admin', httpLogger, logRequest, protect, requireRole(['admin']), getAdminDashboard);
router.put('/profile/image', httpLogger, logRequest, protect, csrfProtect, updateProfileImage);
router.put('/profile/username', httpLogger, logRequest, protect, csrfProtect, updateUsername);

export default router;