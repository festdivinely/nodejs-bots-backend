import express from "express";
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
    verifyDeviceCode,
    verifyResetToken,
    cleanupExpiredData,
    setupTOTP,
    verifyTOTP,
    disableTOTP, // Add disableTOTP
} from "../controllers/authController.js";
import { protect, requireRole, csrfProtect } from "../middleware/authMiddleware.js";
import {
    registerLimiter,
    loginLimiter,
    verifyLimiter,
    refreshLimiter,
    logRequest,
    resetLimiter
} from "../helpers/helperFunctions.js";

const router = express.Router();

// TOTP Routes
router.post("/setup-totp", logRequest, protect, csrfProtect, setupTOTP);
router.post("/verify-totp", logRequest, protect, csrfProtect, verifyTOTP);
router.post("/disable-totp", logRequest, protect, csrfProtect, disableTOTP); // Add disable route

// Public routes
router.post("/register", logRequest, registerLimiter, register);
router.post("/login", logRequest, loginLimiter, login);
router.post("/verify-device-code", logRequest, loginLimiter, verifyDeviceCode);
router.post("/verify-email", logRequest, verifyLimiter, verifyEmail);
router.post("/request-password-reset", logRequest, resetLimiter, requestPasswordReset);
router.post("/reset-password/:token", logRequest, resetLimiter, resetPassword);
router.post("/refresh-token", logRequest, refreshLimiter, refreshToken);
router.get("/verify-reset-token/:token", logRequest, resetLimiter, verifyResetToken);

// Protected routes
router.post("/logout", logRequest, protect, csrfProtect, logout);
router.get("/profile", logRequest, protect, getProfile);
router.get("/admin", logRequest, protect, requireRole(["admin"]), getAdminDashboard);
router.put("/profile/image", logRequest, protect, csrfProtect, updateProfileImage);
router.put("/profile/username", logRequest, protect, csrfProtect, updateUsername);

// Admin only cleanup route (optional)
router.post("/cleanup", logRequest, protect, requireRole(["admin"]), cleanupExpiredData);

export default router;