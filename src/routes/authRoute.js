import { Router } from "express";
import rateLimit from "express-rate-limit";
import {
    login,
    register,
    logout,
    requestPasswordReset,
    resetPassword,
    verifyEmail,
    refreshToken,
    updateProfileImage,
    updateUsername,
    getProfile,
    getAdminDashboard,
    verifyDevice,
} from "../controllers/authController.js";
import { protect, requireRole, csrfProtect } from "../middleware/authMiddleware.js";
import { logger } from "../logger/logger.js";
import requestIp from "request-ip";

const router = Router();

// Log route initialization
logger.info("Initializing auth routes", { route: "/api/auth", timestamp: new Date().toISOString() });

// Rate limiters
const registerLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 5,
    message: "Too many registration attempts, please try again later",
    standardHeaders: true,
    legacyHeaders: false,
});

const loginLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 5,
    message: "Too many login attempts, please try again later",
    standardHeaders: true,
    legacyHeaders: false,
});

const verifyDeviceLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 3,
    message: "Too many OTP attempts, please try again later",
    standardHeaders: true,
    legacyHeaders: false,
});

const resetLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 3,
    message: "Too many password reset requests, please try again later",
    standardHeaders: true,
    legacyHeaders: false,
});

const refreshLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 10,
    message: "Too many refresh attempts, please try again later",
    standardHeaders: true,
    legacyHeaders: false,
});

const verifyLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 5,
    message: "Too many verification attempts, please try again later",
    standardHeaders: true,
    legacyHeaders: false,
});

// Middleware to log request details
const logRequest = (req, res, next) => {
    logger.info(`${req.method} ${req.originalUrl} route accessed`, {
        method: req.method,
        path: req.originalUrl,
        userId: req.user?.id,
        ip: requestIp.getClientIp(req),
        userAgent: req.headers["user-agent"],
        timestamp: new Date().toISOString(),
    });
    next();
};

// Register new user
router.post("/register", registerLimiter, logRequest, register);

// Login
router.post("/login", loginLimiter, logRequest, login);

// Verify device (OTP for new device)
router.post("/verify-device", verifyDeviceLimiter, logRequest, verifyDevice);

// Logout (requires auth and CSRF)
router.post("/logout", protect, csrfProtect, logRequest, logout);

// Request password reset
router.post("/request-password-reset", resetLimiter, logRequest, requestPasswordReset);

// Reset password using token
router.post("/reset-password/:token", resetLimiter, logRequest, resetPassword);

// Verify email with token
router.post("/verify-email", verifyLimiter, logRequest, verifyEmail);

// Refresh JWT access token
router.post("/refresh-token", refreshLimiter, logRequest, refreshToken);

// Get user profile (requires auth)
router.get("/profile", protect, logRequest, getProfile);

// Admin dashboard (requires auth and admin role)
router.get("/admin", protect, requireRole(["admin"]), logRequest, getAdminDashboard);

// Update profile image (requires auth and CSRF)
router.put("/profile/image", protect, csrfProtect, logRequest, updateProfileImage);

// Update username (requires auth and CSRF)
router.put("/profile/username", protect, csrfProtect, logRequest, updateUsername);

export default router;