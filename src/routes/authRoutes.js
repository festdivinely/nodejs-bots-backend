import express from "express"; // Change this line
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
    verifyResetToken,
} from "../controllers/authController.js";
import { protect, requireRole, csrfProtect } from "../middleware/authMiddleware.js";
import requestIp from "request-ip";

const router = express.Router(); // And this line

// Route initialization log
console.info('Initializing auth routes', {
    route: '/api/auth',
    timestamp: new Date().toISOString()
});

// === RATE LIMITERS ===
const registerLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 5,
    message: 'Too many registration attempts, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        console.warn('Rate limit exceeded for register', {
            ip: requestIp.getClientIp(req),
            path: req.originalUrl,
            timestamp: new Date().toISOString(),
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
        console.warn('Rate limit exceeded for login', {
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
        console.warn('Rate limit exceeded for verify-device', {
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
        console.warn('Rate limit exceeded for resend-verify-device', {
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
        console.warn('Rate limit exceeded for reset-password', {
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
        console.warn('Rate limit exceeded for refresh-token', {
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
        console.warn('Rate limit exceeded for verify-email', {
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
        console.warn('Rate limit exceeded for resend-verify-email', {
            ip: requestIp.getClientIp(req),
            path: req.originalUrl,
        });
        res.status(429).json({ message: 'Too many resend verification email attempts, please try again later' });
    },
});

// === ENHANCED REQUEST LOGGER (replaces httpLogger + old logRequest) ===
const logRequest = (req, res, next) => {
    const start = Date.now();

    // Log when response is finished
    res.on("finish", () => {
        const duration = Date.now() - start;
        console.info("HTTP Request Completed", {
            method: req.method,
            path: req.originalUrl,
            status: res.statusCode,
            duration: `${duration}ms`,
            ip: requestIp.getClientIp(req) || "unknown",
            userAgent: req.headers["user-agent"] || "unknown",
            userId: req.user?.id || "unauthenticated",
            body: (req.method === "POST" || req.method === "PUT" || req.method === "PATCH")
                ? {
                    ...req.body,
                    password: req.body.password ? "[REDACTED]" : undefined,
                    totp: req.body.totp ? "[REDACTED]" : undefined,
                    otp: req.body.otp ? "[REDACTED]" : undefined,
                    token: req.body.token ? "[HIDDEN]" : undefined,
                }
                : undefined,
            timestamp: new Date().toISOString(),
        });
    });

    next();
};

// === ROUTES ===
router.post('/register', logRequest, registerLimiter, register);
router.post('/login', logRequest, loginLimiter, login);
router.post('/verify-device', logRequest, verifyDeviceLimiter, verifyDevice);
router.post('/resend-verify-device', logRequest, resendVerifyDeviceLimiter, resendVerifyDevice);
router.post('/logout', logRequest, protect, csrfProtect, logout);
router.post('/request-password-reset', logRequest, resetLimiter, requestPasswordReset);
router.post('/reset-password/:token', logRequest, resetLimiter, resetPassword);
router.post('/verify-email', logRequest, verifyLimiter, verifyEmail);
router.post('/resend-verify-email', logRequest, resendVerifyEmailLimiter, resendVerifyEmail);
router.post('/refresh-token', logRequest, refreshLimiter, refreshToken);
router.get('/profile', logRequest, protect, getProfile);
router.get('/admin', logRequest, protect, requireRole(['admin']), getAdminDashboard);
router.put('/profile/image', logRequest, protect, csrfProtect, updateProfileImage);
router.put('/profile/username', logRequest, protect, csrfProtect, updateUsername);
router.get('/verify-reset-token/:token', logRequest, resetLimiter, verifyResetToken);

export default router;