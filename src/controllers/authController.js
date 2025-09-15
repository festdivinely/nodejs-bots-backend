import jwt from "jsonwebtoken";
import Users from "../models/userModel.js";
import bcrypt from "bcryptjs";
import ms from "ms";
import dotenv from "dotenv";
import asyncHandler from "express-async-handler";
import { sanitizeUser } from "../utility/sanitizeUser.js";
import cloudinary from "../config/cloudinarydb.js";
import { sendVerificationEmail } from "../utility/email.js";
import { sendPasswordResetEmail } from "../utility/passwordResetEmail.js";
import { sendSuspiciousActivityEmail } from "../utility/suspiciousEmail.js";
import { sendDeviceVerificationEmail } from "../utility/deviceVerifyEmail.js";
import { logger } from "../logger/logger.js";
import requestIp from "request-ip";
import geoip from "geoip-lite";
import Redis from "ioredis";
import { body, query, validationResult } from "express-validator";
import speakeasy from "speakeasy";

dotenv.config();

const REFRESH_TOKEN_EXPIRES = "15d";
const ISSUER = process.env.ISSUER || "quantumrobots.com";
const AUDIENCE = process.env.AUDIENCE || "api.quantumrobots.com";
const privateKey = Buffer.from(process.env.PRIVATE_KEY, "base64").toString("utf-8");
const publicKey = Buffer.from(process.env.PUBLIC_KEY, "base64").toString("utf-8");
const DEV_MODE = process.env.DEV_MODE === "true";
const redis = process.env.REDIS_URL ? new Redis(process.env.REDIS_URL) : null;

if (!privateKey || !publicKey) {
    logger.error("Missing PRIVATE_KEY or PUBLIC_KEY environment variables");
    throw new Error("Missing PRIVATE_KEY or PUBLIC_KEY environment variables");
}

// Blacklist tokens
const blacklistToken = async (token) => {
    if (redis) {
        await redis.set(`blacklist:${token}`, "true", "EX", ms(REFRESH_TOKEN_EXPIRES) / 1000);
    } else {
        logger.warn("No Redis; skipping blacklist for token");
    }
};

const isBlacklisted = async (token) => {
    if (redis) {
        return await redis.get(`blacklist:${token}`) !== null;
    }
    return false;
};


// Middleware to add security headers
const setSecurityHeaders = (req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; object-src 'none';");
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
};

// Validation rules for username
const usernameValidation = [
    body('username')
        .trim()
        .isLength({ min: 3, max: 30 })
        .withMessage('Username must be between 3 and 30 characters.')
        .matches(/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,28}[a-zA-Z0-9]$/)
        .withMessage('Username must start and end with a letter or number, and can only contain letters, numbers, underscores, hyphens, or single periods.')
        .not()
        .matches(/([._-])\1/)
        .withMessage('Username cannot contain consecutive underscores, hyphens, or periods.'),
];

// Validation rules for password
const passwordValidation = [
    body('password')
        .trim()
        .isLength({ min: 8, max: 50 })
        .withMessage('Password must be between 8 and 50 characters.')
        .matches(/^[^\s].*[^\s]$/)
        .withMessage('Password cannot start or end with a space.')
        .matches(/^[A-Za-z0-9@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]*$/)
        .withMessage('Password can only contain letters, numbers, and common special characters.')
        .not()
        .matches(/([@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])\1{2,}/)
        .withMessage('Password cannot contain three or more consecutive special characters.'),
];

// Validation middleware
const validate = (validations) => [
    ...validations,
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logger.warn('Input validation failed', {
                errors: errors.array(),
                route: req.originalUrl,
                ip: requestIp.getClientIp(req),
            });
            return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
        }
        next();
    },
];

// Register endpoint
export const register = [
    setSecurityHeaders,
    validate([
        ...usernameValidation,
        body('email').isEmail().withMessage('Invalid email format'),
        ...passwordValidation,
    ]),
    asyncHandler(async (req, res) => {
        const { username, email, password } = req.body;
        const ip = requestIp.getClientIp(req);

        try {
            // Check if user already exists
            const exists = await Users.findOne({ $or: [{ email }, { username }] });
            if (exists) {
                logger.warn('User already exists', { email, username, ip, route: req.originalUrl });
                return res.status(400).json({ message: 'User with this email or username already exists' });
            }

            // Create user
            const profileImage = `https://api.dicebear.com/9.x/avataaars/svg?seed=${username}`;
            const user = new Users({
                username,
                email,
                password,
                profileImage,
                isActive: false,
            });

            // Generate verification token
            await user.generateResetToken('email_verification');
            await user.save();
            logger.info('User registered successfully', { email, userId: user._id, ip, route: req.originalUrl });

            // Send verification email with token
            const emailSent = await sendVerificationEmail(email, null, user.emailVerifyToken);
            if (!emailSent) {
                logger.error('Failed to send verification email', { email, ip, route: req.originalUrl });
                return res.status(500).json({ message: 'Failed to send verification email' });
            }

            res.status(201).json({ message: 'Verification email sent. Please check your inbox and paste the token in the app.' });
        } catch (error) {
            logger.error('Registration error', { error: error.message, email, ip, route: req.originalUrl });
            res.status(500).json({ message: 'Server error during registration' });
        }
    }),
];

// Verify Email endpoint
export const verifyEmail = [
    setSecurityHeaders,
    validate([
        body('token')
            .notEmpty()
            .withMessage('Verification token is required'),
    ]),
    asyncHandler(async (req, res) => {
        const { token } = req.body;
        const ip = requestIp.getClientIp(req);

        try {
            // Find user by token and check expiry
            const user = await Users.findOne({
                emailVerifyToken: token,
                emailVerifyExpires: { $gt: Date.now() },
            });

            if (!user) {
                logger.warn('Invalid or expired verification token', { ip, route: req.originalUrl });
                return res.status(400).json({ message: 'Invalid or expired verification token' });
            }

            // Update user status
            user.emailVerifyToken = undefined;
            user.emailVerifyExpires = undefined;
            user.isActive = true;
            await user.save();

            logger.info('Email verified successfully', { userId: user._id, email: user.email, ip, route: req.originalUrl });
            res.status(200).json({ message: 'Email verified successfully! You can now log in.' });
        } catch (error) {
            logger.error('Email verification error', { error: error.message, ip, route: req.originalUrl });
            res.status(500).json({ message: 'Server error during email verification' });
        }
    }),
];

// ======================= Login =======================
export const login = [
    validate([
        body("usernameOrEmail").notEmpty().withMessage("Username or email is required"),
        body("password").notEmpty().withMessage("Password is required"),
        body("fingerprint").custom((value) => DEV_MODE || value).withMessage("Device fingerprint is required"),
        body("totp").optional().isLength({ min: 6, max: 6 }).withMessage("TOTP must be 6 digits"),
    ]),
    asyncHandler(async (req, res) => {
        const { usernameOrEmail, password, fingerprint, totp } = req.body;
        const ip = requestIp.getClientIp(req);
        const geo = geoip.lookup(ip);
        const country = geo ? geo.country : "unknown";
        const deviceInfo = req.headers["user-agent"];

        const user = await Users.findOne({
            $or: [{ email: usernameOrEmail }, { username: usernameOrEmail }],
        });
        if (!user || !user.isActive || !(await user.verifyPassword(password))) {
            logger.warn("Invalid login attempt", { usernameOrEmail, ip });
            return res.status(400).json({ message: "Invalid credentials or inactive account" });
        }

        // 2FA: If enabled, verify TOTP
        if (user.twoFactorEnabled && !DEV_MODE) {
            if (!totp) {
                logger.warn("TOTP required", { userId: user._id, ip });
                return res.status(400).json({ message: "TOTP required", requiresTotp: true });
            }
            const isValid = speakeasy.totp.verify({
                secret: user.twoFactorSecret, // Assume stored in model
                encoding: "base32",
                token: totp,
            });
            if (!isValid) {
                logger.warn("Invalid TOTP", { userId: user._id, ip });
                return res.status(400).json({ message: "Invalid TOTP" });
            }
        }

        // New device detection
        const existingFingerprints = user.sessions.map(s => s.fingerprint);
        const isNewDevice = fingerprint && !existingFingerprints.includes(fingerprint) && !DEV_MODE;

        if (isNewDevice) {
            const otp = await user.generateDeviceVerifyToken(fingerprint);
            const emailSent = await sendDeviceVerificationEmail(user.email, otp, deviceInfo, ip);
            if (!emailSent) {
                logger.error("Failed to send device verification email", { email: user.email, ip });
                return res.status(500).json({ message: "Failed to send verification email" });
            }
            logger.info("New device detected; OTP sent", { userId: user._id, fingerprint, ip });
            return res.status(200).json({ message: "New device detected. Verify with OTP sent to your email.", requiresOtp: true });
        }

        // Update login audit fields
        user.lastLogin = new Date();
        user.lastLoginIp = ip;
        user.lastLoginDevice = deviceInfo;
        await user.cleanSessions();

        const accessToken = await user.generateAccessToken();
        const refreshToken = await user.generateRefreshToken(fingerprint || "dev-mode", ip, country, deviceInfo);

        await user.save();
        logger.info("Login successful", { userId: user._id, ip, country });

        return res.json({
            accessToken,
            refreshToken,
            csrfToken: user.sessions[user.sessions.length - 1].csrfToken,
            user: sanitizeUser(user),
        });
    })
];

// ======================= Verify Device =======================
export const verifyDevice = [
    validate([
        body("otp").isLength({ min: 6, max: 6 }).withMessage("OTP must be 6 characters"),
        body("fingerprint").notEmpty().withMessage("Device fingerprint is required"),
        body("usernameOrEmail").notEmpty().withMessage("Username or email is required"),
    ]),
    asyncHandler(async (req, res) => {
        const { otp, fingerprint, usernameOrEmail } = req.body;
        const ip = requestIp.getClientIp(req);
        const geo = geoip.lookup(ip);
        const country = geo ? geo.country : "unknown";
        const deviceInfo = req.headers["user-agent"];

        const user = await Users.findOne({
            $or: [{ email: usernameOrEmail }, { username: usernameOrEmail }],
            deviceVerifyFingerprint: fingerprint,
            deviceVerifyExpires: { $gt: Date.now() },
        });

        if (!user) {
            logger.warn("Invalid or expired device verification", {
                ip,
                usernameOrEmail,
                fingerprint,
                currentTime: new Date(),
            });
            return res.status(400).json({ message: "Invalid or expired verification" });
        }

        const isMatch = await bcrypt.compare(otp, user.deviceVerifyToken);
        if (!isMatch) {
            logger.warn("Invalid OTP", { userId: user._id, ip });
            return res.status(400).json({ message: "Invalid OTP" });
        }

        // Clear temp fields
        user.deviceVerifyToken = undefined;
        user.deviceVerifyExpires = undefined;
        user.deviceVerifyFingerprint = undefined;

        // Update audit fields
        user.lastLogin = new Date();
        user.lastLoginIp = ip;
        user.lastLoginDevice = deviceInfo;
        await user.cleanSessions();

        const accessToken = await user.generateAccessToken();
        const refreshToken = await user.generateRefreshToken(fingerprint, ip, country, deviceInfo);
        await user.save();

        logger.info("Device verified successfully", { userId: user._id, fingerprint, ip });

        res.json({
            accessToken,
            refreshToken,
            csrfToken: user.sessions[user.sessions.length - 1].csrfToken,
            user: sanitizeUser(user),
        });
    })
];

// ======================= Refresh Token =======================
export const refreshToken = [
    validate([
        body("refreshToken").notEmpty().withMessage("Refresh token is required"),
        body("fingerprint").custom((value) => DEV_MODE || value).withMessage("Device fingerprint is required"),
    ]),
    asyncHandler(async (req, res) => {
        const { refreshToken, fingerprint } = req.body;
        const ip = requestIp.getClientIp(req);
        const geo = geoip.lookup(ip);
        const country = geo ? geo.country : "unknown";
        const deviceInfo = req.headers["user-agent"];

        if (await isBlacklisted(refreshToken)) {
            logger.warn("Blacklisted refresh token", { ip, route: req.originalUrl });
            return res.status(401).json({ message: "Invalid token" });
        }

        const payload = jwt.verify(refreshToken, publicKey, {
            algorithms: ["RS256"],
            issuer: ISSUER,
            audience: AUDIENCE,
        });
        const user = await Users.findById(payload.userId);
        if (!user) {
            logger.warn("User not found for refresh token", { userId: payload.userId, ip, route: req.originalUrl });
            return res.status(404).json({ message: "User not found" });
        }

        const sessionIndex = user.sessions.findIndex((s) => s.token === refreshToken);
        if (sessionIndex === -1) {
            logger.warn("Invalid refresh token", { userId: user._id, ip, route: req.originalUrl });
            return res.status(401).json({ message: "Invalid token" });
        }
        const session = user.sessions[sessionIndex];

        // Fingerprint mismatch check
        if (!DEV_MODE && fingerprint && session.fingerprint !== fingerprint) {
            const trustedFingerprints = user.sessions.map(s => s.fingerprint);
            if (!trustedFingerprints.includes(fingerprint)) {
                await sendSuspiciousActivityEmail(user.email, {
                    ip,
                    country,
                    deviceInfo,
                    message: "New device detected during refresh. Re-login required.",
                });
                user.sessions = [];
                await user.save();
                logger.warn("Fingerprint mismatch, sessions cleared", { userId: user._id, ip });
                return res.status(401).json({ message: "New device detected. Please re-login to verify." });
            }
        }

        if (session.used) {
            user.sessions = [];
            await user.save();
            logger.warn("Token reuse detected, sessions cleared", { userId: user._id, ip, route: req.originalUrl });
            return res.status(401).json({ message: "Token reuse detected - all sessions invalidated" });
        }

        // Rotate token
        user.sessions[sessionIndex].used = true;
        const newRefresh = await user.generateRefreshToken(fingerprint || session.fingerprint, ip, country, deviceInfo);
        await user.cleanSessions();
        await user.save();

        const newAccess = await user.generateAccessToken();
        logger.info("Refresh token rotated successfully", { userId: user._id, ip, country });

        res.json({
            accessToken: newAccess,
            refreshToken: newRefresh,
            csrfToken: user.sessions[user.sessions.length - 1].csrfToken,
        });
    })
];

// ======================= Logout =======================
export const logout = [
    validate([body("refreshToken").notEmpty().withMessage("Refresh token is required")]),
    asyncHandler(async (req, res) => {
        const { refreshToken } = req.body;
        const ip = requestIp.getClientIp(req);
        const payload = jwt.verify(refreshToken, publicKey, { algorithms: ["RS256"] });
        const user = await Users.findById(payload.userId);
        if (user) {
            user.sessions = user.sessions.filter((s) => s.token !== refreshToken);
            await blacklistToken(refreshToken);
            await user.save();
            logger.info("User logged out successfully", { userId: user._id, ip, route: req.originalUrl });
        }
        res.json({ message: "Logged out successfully" });
    })
];

// ======================= Request Password Reset =======================
export const requestPasswordReset = [
    validate([body("email").isEmail().withMessage("Invalid email format")]),
    asyncHandler(async (req, res) => {
        const { email } = req.body;
        const ip = requestIp.getClientIp(req);
        const user = await Users.findOne({ email });
        if (!user) {
            logger.warn("User not found for password reset", { email, ip, route: req.originalUrl });
            return res.status(404).json({ message: "User not found" });
        }
        if (!user.isActive) {
            logger.warn("Email not verified for password reset", { email, ip, route: req.originalUrl });
            return res.status(401).json({ message: "Email not verified" });
        }

        const resetToken = await user.generateResetToken("password_reset");
        await user.save();

        const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;
        const emailSent = await sendPasswordResetEmail(email, resetUrl);

        if (!emailSent) {
            logger.error("Failed to send password reset email", { email, ip, route: req.originalUrl });
            return res.status(500).json({ message: "Failed to send password reset email" });
        }

        logger.info("Password reset email sent", { email, ip, route: req.originalUrl });
        res.json({ message: "Password reset email sent. Please check your inbox." });
    })
];

// ======================= Reset Password =======================
export const resetPassword = [
    validate([
        query("token").notEmpty().withMessage("Reset token is required"),
        body("newPassword")
            .matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/)
            .withMessage("Password must be at least 8 characters, include a letter, number, and special character"),
        body("confirmPassword")
            .custom((value, { req }) => value === req.body.newPassword)
            .withMessage("Passwords do not match"),
    ]),
    asyncHandler(async (req, res) => {
        const { token } = req.query;
        const { newPassword } = req.body;
        const ip = requestIp.getClientIp(req);

        const user = await Users.findOne({
            passwordResetToken: token,
            passwordResetExpires: { $gt: Date.now() },
        });
        if (!user) {
            logger.warn("Invalid or expired reset token", { ip, route: req.originalUrl });
            return res.status(400).json({ message: "Invalid or expired reset token" });
        }

        const isSamePassword = await bcrypt.compare(newPassword, user.password);
        if (isSamePassword) {
            logger.warn("New password same as old", { userId: user._id, ip, route: req.originalUrl });
            return res.status(400).json({ message: "New password cannot be the same as the old password" });
        }

        user.password = newPassword; // hashed by pre-save hook
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save();

        logger.info("Password reset successfully", { userId: user._id, email: user.email, ip, route: req.originalUrl });
        res.json({ message: "Password reset successful! You can now log in with your new password." });
    })
];

// ======================= Update Profile Image =======================
export const updateProfileImage = [
    validate([body("image").notEmpty().withMessage("Image is required")]),
    asyncHandler(async (req, res) => {
        const { image } = req.body;
        const userId = req.user?.id;
        const ip = requestIp.getClientIp(req);

        const user = await Users.findById(userId);
        if (!user) {
            logger.warn("User not found for profile image update", { userId, ip, route: req.originalUrl });
            return res.status(404).json({ message: "User not found" });
        }
        if (!user.isActive) {
            logger.warn("Email not verified for profile image update", { userId, ip, route: req.originalUrl });
            return res.status(403).json({ message: "Only verified users can update profile image" });
        }

        const uploaded = await cloudinary.uploader.upload(image, {
            folder: "profile_images",
            public_id: `user_${user._id}_${Date.now()}`,
            overwrite: true,
            resource_type: "auto",
        });

        user.profileImage = uploaded.secure_url;
        await user.save();

        logger.info("Profile image updated successfully", { userId, email: user.email, ip, route: req.originalUrl });
        res.status(200).json({
            message: "Profile image updated successfully",
            profileImage: user.profileImage,
        });
    })
];

// ======================= Update Username =======================
export const updateUsername = [
    validate([
        body("newUsername")
            .matches(/^[a-zA-Z0-9_-]{3,}$/)
            .withMessage("Username must be at least 3 characters, alphanumeric, underscores, or hyphens"),
    ]),
    asyncHandler(async (req, res) => {
        const { newUsername } = req.body;
        const userId = req.user?.id;
        const ip = requestIp.getClientIp(req);

        const user = await Users.findById(userId);
        if (!user) {
            logger.warn("User not found for username update", { userId, ip, route: req.originalUrl });
            return res.status(404).json({ message: "User not found" });
        }
        if (!user.isActive) {
            logger.warn("Email not verified for username update", { userId, ip, route: req.originalUrl });
            return res.status(403).json({ message: "Only verified users can update username" });
        }

        const existing = await Users.findOne({ username: newUsername });
        if (existing) {
            logger.warn("Username already taken", { userId, newUsername, ip, route: req.originalUrl });
            return res.status(400).json({ message: "Username already taken" });
        }

        user.username = newUsername;
        await user.save();

        logger.info("Username updated successfully", { userId, username: newUsername, ip, route: req.originalUrl });
        res.status(200).json({
            message: "Username updated successfully",
            username: user.username,
        });
    })
];

// ======================= Get User Profile =======================
export const getProfile = asyncHandler(async (req, res) => {
    const ip = requestIp.getClientIp(req);
    const user = await Users.findById(req.user.id);

    if (!user) {
        logger.warn("User not found for profile fetch", { userId: req.user.id, ip, route: req.originalUrl });
        return res.status(404).json({ message: "User not found" });
    }

    logger.info("Profile fetched successfully", { userId: user._id, email: user.email, ip, route: req.originalUrl });
    res.status(200).json({
        message: "Profile fetched successfully",
        user: sanitizeUser(user),
    });
});

// ======================= Admin Dashboard =======================
export const getAdminDashboard = asyncHandler(async (req, res) => {
    const ip = requestIp.getClientIp(req);
    const users = await Users.find().select("username email role isActive createdAt");

    logger.info("Admin dashboard accessed", { userId: req.user.id, email: req.user.email, ip, route: req.originalUrl });
    res.status(200).json({
        message: `Admin access granted for ${req.user.email}`,
        totalUsers: users.length,
        users,
    });
});