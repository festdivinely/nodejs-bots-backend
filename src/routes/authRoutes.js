// routes/authRoutes.js
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
    verifyResetCode,
    cleanupExpiredData,
    setupTOTP,
    setupTOTPLogin,
    verifyTOTPLogin,
    verifyTOTPSetupLogin,
    verifyTOTPSetup,
    disableTOTP,
    resendVerifyEmail,
    resendVerifyDevice
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

import { trimRequestBody } from "../middleware/trimMiddleware.js";

const router = express.Router();

// TOTP Routes
router.post("/setup-totp", logRequest, trimRequestBody, protect, csrfProtect, setupTOTP);
router.post("/setup-totp-login", logRequest, trimRequestBody, loginLimiter, setupTOTPLogin);
router.post("/verify-totp-setup", logRequest, trimRequestBody, protect, csrfProtect, verifyTOTPSetup);
router.post("/verify-totp-setup-login", logRequest, trimRequestBody, loginLimiter, verifyTOTPSetupLogin);
router.post('/verify-totp-login', logRequest, trimRequestBody, loginLimiter, verifyTOTPLogin);
router.post("/disable-totp", logRequest, trimRequestBody, protect, csrfProtect, disableTOTP);

// Public routes
router.post("/register", logRequest, trimRequestBody, registerLimiter, register);
router.post("/login", logRequest, trimRequestBody, loginLimiter, login);
router.post("/verify-device", logRequest, trimRequestBody, loginLimiter, verifyDeviceCode);
router.post("/resend-verify-device", logRequest, trimRequestBody, loginLimiter, resendVerifyDevice);
router.post("/verify-email", logRequest, trimRequestBody, verifyLimiter, verifyEmail);
router.post('/resend-verify-email', logRequest, trimRequestBody, verifyLimiter, resendVerifyEmail);
router.post("/request-password-reset", logRequest, trimRequestBody, resetLimiter, requestPasswordReset);
router.post("/verify-reset-code", logRequest, trimRequestBody, resetLimiter, verifyResetCode);
router.post("/reset-password", logRequest, trimRequestBody, resetLimiter, resetPassword);
router.post("/refresh-token", logRequest, trimRequestBody, refreshLimiter, refreshToken);

// Protected routes
router.post("/logout", logRequest, trimRequestBody, protect, csrfProtect, logout);
router.get("/profile", logRequest, protect, getProfile);
router.get("/admin", logRequest, protect, requireRole(["admin"]), getAdminDashboard);
router.put("/profile/image", logRequest, trimRequestBody, protect, csrfProtect, updateProfileImage);
router.put("/profile/username", logRequest, trimRequestBody, protect, csrfProtect, updateUsername);

// Admin only cleanup route
router.post("/cleanup", logRequest, trimRequestBody, protect, requireRole(["admin"]), cleanupExpiredData);

export default router;