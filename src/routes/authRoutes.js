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
    verifyTOTPSetupLogin,
    verifyTOTPSetup,
    disableTOTP,
    resendVerifyEmail,
    resendVerifyDevice // ✅ ADD THIS IMPORT
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
router.post("/setup-totp-login", logRequest, loginLimiter, setupTOTPLogin);
router.post("/verify-totp-setup", logRequest, protect, csrfProtect, verifyTOTPSetup);
router.post("/verify-totp-setup-login", logRequest, loginLimiter, verifyTOTPSetupLogin);
router.post("/disable-totp", logRequest, protect, csrfProtect, disableTOTP);

// Public routes
router.post("/register", logRequest, registerLimiter, register);
router.post("/login", logRequest, loginLimiter, login);
router.post("/verify-device", logRequest, loginLimiter, verifyDeviceCode);
router.post("/resend-verify-device", logRequest, loginLimiter, resendVerifyDevice); // ✅ ADD THIS ROUTE
router.post("/verify-email", logRequest, verifyLimiter, verifyEmail);
router.post('/resend-verify-email', logRequest, verifyLimiter, resendVerifyEmail);
router.post("/request-password-reset", logRequest, resetLimiter, requestPasswordReset);
router.post("/verify-reset-code", logRequest, resetLimiter, verifyResetCode);
router.post("/reset-password", logRequest, resetLimiter, resetPassword);
router.post("/refresh-token", logRequest, refreshLimiter, refreshToken);

// Protected routes
router.post("/logout", logRequest, protect, csrfProtect, logout);
router.get("/profile", logRequest, protect, getProfile);
router.get("/admin", logRequest, protect, requireRole(["admin"]), getAdminDashboard);
router.put("/profile/image", logRequest, protect, csrfProtect, updateProfileImage);
router.put("/profile/username", logRequest, protect, csrfProtect, updateUsername);

// Admin only cleanup route
router.post("/cleanup", logRequest, protect, requireRole(["admin"]), cleanupExpiredData);

export default router;