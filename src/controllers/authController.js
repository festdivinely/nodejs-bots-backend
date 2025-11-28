import jwt from "jsonwebtoken";
import Users from "../models/userModel.js";
import bcrypt from "bcryptjs";
import ms from "ms";
import dotenv from "dotenv";
import asyncHandler from "express-async-handler";
import { sanitizeUser } from "../utility/sanitizeUser.js";
import cloudinary from "../config/cloudinarydb.js";
import requestIp from "request-ip";
import geoip from "geoip-lite";
import Redis from "ioredis";
import { body, query, validationResult } from "express-validator";
import speakeasy from "speakeasy";

dotenv.config();

const REFRESH_TOKEN_EXPIRES = '15d';
const ISSUER = process.env.ISSUER || 'quantumrobots.com';
const AUDIENCE = process.env.AUDIENCE || 'api.quantumrobots.com';
const privateKey = Buffer.from(process.env.PRIVATE_KEY, 'base64').toString('utf-8');
const publicKey = Buffer.from(process.env.PUBLIC_KEY, 'base64').toString('utf-8');
const DEV_MODE = process.env.DEV_MODE === 'true';
const EMAIL_SERVICE_DOMAIN = process.env.EMAIL_SERVICE_DOMAIN || 'https://choir-song-project-typing-1e66.vercel.app';
const redis = process.env.REDIS_URL ? new Redis(process.env.REDIS_URL) : null;

if (!privateKey || !publicKey) {
    console.error('Missing PRIVATE_KEY or PUBLIC_KEY environment variables');
    throw new Error('Missing PRIVATE_KEY or PUBLIC_KEY environment variables');
}

const blacklistToken = async (token) => {
    if (redis) {
        await redis.set(`blacklist:${token}`, 'true', 'EX', ms(REFRESH_TOKEN_EXPIRES) / 1000);
        console.info('Token blacklisted', { token: '[REDACTED]' });
    } else {
        console.warn('No Redis; skipping blacklist for token');
    }
};

const isBlacklisted = async (token) => {
    if (redis) {
        return (await redis.get(`blacklist:${token}`)) !== null;
    }
    return false;
};

const setSecurityHeaders = (req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; object-src 'none';");
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
};

const validateCsrfToken = (req, res, next) => {
    const csrfToken = req.headers['x-csrf-token'];
    if (!DEV_MODE && !csrfToken) {
        console.warn('CSRF token missing', {
            route: req.originalUrl,
            ip: requestIp.getClientIp(req),
            timestamp: new Date().toISOString(),
        });
        return res.status(403).json({ message: 'CSRF token required' });
    }
    next();
};

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

const validate = (validations) => [
    ...validations,
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            console.warn('Input validation failed', {
                errors: errors.array(),
                route: req.originalUrl,
                ip: requestIp.getClientIp(req),
                timestamp: new Date().toISOString(),
            });
            return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
        }
        next();
    },
];

// Helper function to get client info
const getClientInfo = (req) => {
    const ip = requestIp.getClientIp(req);
    const geo = geoip.lookup(ip);
    const country = geo ? geo.country : 'unknown';
    const deviceInfo = req.headers['user-agent'] || 'unknown';

    return { ip, country, deviceInfo };
};

// Send email data to external service
const sendEmailData = async (emailType, to, data) => {
    try {
        const response = await fetch(`${EMAIL_SERVICE_DOMAIN}/api/send-email`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                type: emailType,
                to: to,
                data: data
            })
        });

        return response.ok;
    } catch (error) {
        console.error('Email service error:', error.message);
        return false;
    }
};

export const register = [
    setSecurityHeaders,
    validate([
        ...usernameValidation,
        body('email').isEmail().withMessage('Invalid email format'),
        ...passwordValidation,
        body('fingerprint').custom((value) => DEV_MODE || value).withMessage('Device fingerprint is required'),
        // Note: enableTOTP is optional, so no validation needed
    ]),
    asyncHandler(async (req, res) => {
        const { username, email, password, fingerprint, enableTOTP } = req.body; // Add enableTOTP here
        const { ip, country, deviceInfo } = getClientInfo(req);

        console.info('Register route accessed', {
            body: { username, email, password: '[REDACTED]', fingerprint, enableTOTP },
            ip,
            country,
            deviceInfo,
            timestamp: new Date().toISOString(),
        });

        try {
            const existingUser = await Users.findOne({ $or: [{ email }, { username }] });

            // User exists but is NOT verified - resend verification code
            if (existingUser && !existingUser.isActive) {
                console.info('Unverified user attempting to register again', { email, username, ip, country, deviceInfo });

                // Generate new verification code
                const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
                existingUser.emailVerifyToken = verificationCode;
                existingUser.emailVerifyExpires = new Date(Date.now() + 15 * 60 * 1000);

                // If enableTOTP was requested, store it for later
                // In the registration controller, update this part:
                if (enableTOTP) {
                    user.twoFactorEnabled = true; // Mark as enabled but not setup
                    user.twoFactorSetupCompleted = false; // Not yet setup
                    user.pendingTOTPEnable = true; // Keep this for tracking
                }

                await existingUser.save();

                // Send verification email
                const emailSent = await sendEmailData('email_verification', email, {
                    username: existingUser.username,
                    verificationCode: verificationCode,
                    supportEmail: 'support@quantumrobots.com'
                });

                if (!emailSent) {
                    console.error('Failed to resend verification email', { email, ip, country, deviceInfo });
                    return res.status(500).json({ message: 'Failed to send verification email' });
                }

                return res.status(200).json({
                    success: true,
                    message: 'Verification code resent to your email.',
                    requiresEmailVerification: true,
                    email: email
                });
            }

            // User exists and IS verified - cannot register again
            if (existingUser) {
                console.warn('Verified user already exists', { email, username, ip, country, deviceInfo });
                return res.status(400).json({
                    success: false,
                    message: 'User with this email or username already exists',
                    action: 'login'
                });
            }

            // New user - create account
            const profileImage = `https://api.dicebear.com/9.x/avataaars/svg?seed=${username}`;

            const user = new Users({
                username,
                email,
                password,
                profileImage,
                isActive: false,
                // Store the TOTP preference for after email verification
                pendingTOTPEnable: enableTOTP || false
            });

            const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
            user.emailVerifyToken = verificationCode;
            user.emailVerifyExpires = new Date(Date.now() + 15 * 60 * 1000);

            user.devices.push({
                fingerprint: fingerprint,
                status: 'NOT CONFIRMED',
                deviceInfo: deviceInfo,
                ip: ip,
                country: country,
                createdAt: new Date(),
                expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
            });

            await user.save();

            // Send verification email
            const emailSent = await sendEmailData('email_verification', email, {
                username: username,
                verificationCode: verificationCode,
                supportEmail: 'support@quantumrobots.com'
            });

            if (!emailSent) {
                console.error('Failed to send verification email via external service', { email, ip, country, deviceInfo });
                return res.status(500).json({
                    success: false,
                    message: 'Failed to send verification email'
                });
            }

            res.status(201).json({
                success: true,
                message: 'Verification code sent to your email.',
                requiresEmailVerification: true,
                email: email,
                pendingTOTPEnable: enableTOTP || false
            });
        } catch (error) {
            console.error('Registration error', {
                error: error.message,
                stack: error.stack,
                email,
                ip,
                country,
                deviceInfo,
                timestamp: new Date().toISOString(),
            });
            res.status(500).json({
                success: false,
                message: 'Server error during registration'
            });
        }
    }),
];


// Setup TOTP (Generate QR Code)
// Setup TOTP (Generate Secret Only - No QR Code)
export const setupTOTP = [
    asyncHandler(async (req, res) => {
        try {
            const user = await Users.findById(req.user.id);

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found'
                });
            }

            // Generate new secret
            const secret = speakeasy.generateSecret({
                name: `QuantumRobots:${user.email}`,
                issuer: 'Quantum Robots'
            });

            // Store temporary secret
            user.twoFactorSecret = secret.base32;
            user.twoFactorSetupCompleted = false;
            await user.save();

            // Return only the secret, no QR code
            res.json({
                success: true,
                secret: secret.base32, // Only return secret
                message: 'Enter this code manually in Google Authenticator'
            });

        } catch (error) {
            console.error('TOTP setup error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to setup TOTP'
            });
        }
    })
];

// Verify TOTP Code (Used for both setup and login)
export const verifyTOTP = [
    validate([
        body('totpCode').isLength({ min: 6, max: 6 }).withMessage('TOTP code must be 6 digits')
    ]),
    asyncHandler(async (req, res) => {
        const { totpCode } = req.body;

        try {
            const user = await Users.findById(req.user.id);

            if (!user || !user.twoFactorSecret) {
                return res.status(400).json({
                    success: false,
                    message: 'TOTP not setup properly'
                });
            }

            // Verify the code (same logic for setup and login)
            const verified = speakeasy.totp.verify({
                secret: user.twoFactorSecret,
                encoding: 'base32',
                token: totpCode,
                window: 1
            });

            if (!verified) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid TOTP code'
                });
            }

            // If this is setup verification (user not fully setup yet)
            if (!user.twoFactorSetupCompleted) {
                // Generate backup codes
                const backupCodes = Array.from({ length: 8 }, () =>
                    Math.random().toString(36).substring(2, 10).toUpperCase()
                );

                // Hash backup codes
                const hashedBackupCodes = await Promise.all(
                    backupCodes.map(async (code) => await bcrypt.hash(code, 10))
                );

                // Complete TOTP setup
                user.twoFactorEnabled = true;
                user.twoFactorSetupCompleted = true;
                user.twoFactorBackupCodes = hashedBackupCodes;

                await user.save();

                return res.json({
                    success: true,
                    message: 'TOTP setup completed successfully',
                    backupCodes, // Show only once!
                    twoFactorEnabled: true
                });
            } else {
                // This is login verification - user is already setup
                // Generate new tokens for login
                const accessToken = await user.generateAccessToken();
                const refreshToken = await user.generateRefreshToken('login-totp', req.ip, 'unknown', 'TOTP Login');

                await user.save();

                return res.json({
                    success: true,
                    message: 'TOTP verified successfully',
                    accessToken,
                    refreshToken,
                    csrfToken: user.sessions[user.sessions.length - 1].csrfToken,
                    user: sanitizeUser(user)
                });
            }

        } catch (error) {
            console.error('TOTP verification error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to verify TOTP'
            });
        }
    })
];

// Disable TOTP
// Updated disableTOTP controller using the model method
export const disableTOTP = [
    validate([
        body('password').notEmpty().withMessage('Password is required to disable TOTP')
    ]),
    asyncHandler(async (req, res) => {
        const { password } = req.body;

        try {
            const user = await Users.findById(req.user.id);

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found'
                });
            }

            // Verify password before disabling TOTP
            const isPasswordValid = await user.verifyPassword(password);
            if (!isPasswordValid) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid password. Please enter your current password to disable TOTP.'
                });
            }

            // Check if TOTP is actually enabled
            if (!user.twoFactorEnabled) {
                return res.status(400).json({
                    success: false,
                    message: 'Two-factor authentication is not enabled for your account.'
                });
            }

            // Use the model method to disable TOTP
            await user.disableTOTP();

            res.json({
                success: true,
                message: 'Two-factor authentication has been disabled successfully.',
                twoFactorEnabled: false
            });

        } catch (error) {
            console.error('TOTP disable error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to disable TOTP'
            });
        }
    })
];

export const verifyEmail = [
    setSecurityHeaders,
    validate([
        body('code').notEmpty().withMessage('Verification code is required'),
    ]),
    asyncHandler(async (req, res) => {
        const { code } = req.body;
        const { ip, country, deviceInfo } = getClientInfo(req);

        console.info('Verify email route accessed', {
            body: { code: '[REDACTED]' },
            ip,
            country,
            deviceInfo,
            timestamp: new Date().toISOString(),
        });

        try {
            if (!code) {
                console.warn('No verification code provided', { ip, country, deviceInfo });
                return res.status(400).json({
                    message: 'Verification code is required'
                });
            }

            // Find user by verification code
            const user = await Users.findOne({
                emailVerifyToken: code,
                emailVerifyExpires: { $gt: Date.now() },
            });

            if (!user) {
                console.warn('Invalid or expired verification code', {
                    ip, country, deviceInfo
                });

                // Cleanup failed verification
                const expiredUser = await Users.findOne({ emailVerifyToken: code });
                if (expiredUser && !expiredUser.isActive) {
                    await Users.deleteOne({ _id: expiredUser._id });
                }

                return res.status(400).json({
                    message: 'Invalid or expired verification code'
                });
            }

            // Update device status and user activation
            user.devices = user.devices.map(device => ({
                ...device.toObject(),
                status: 'YES IT ME',
                verifiedAt: new Date(),
                expiresAt: undefined
            }));

            user.emailVerifyToken = undefined;
            user.emailVerifyExpires = undefined;
            user.isActive = true;
            await user.save();

            console.info('Email verified and device confirmed', {
                userId: user._id,
                email: user.email,
                ip,
                country,
                deviceInfo
            });

            res.status(200).json({
                message: 'Email verified successfully! You can now log in.',
                verified: true
            });
        } catch (error) {
            console.error('Email verification error', {
                error: error.message,
                stack: error.stack,
                ip,
                country,
                deviceInfo,
                timestamp: new Date().toISOString(),
            });

            // Clean up on error
            try {
                const user = await Users.findOne({ emailVerifyToken: code });
                if (user && !user.isActive) {
                    await Users.deleteOne({ _id: user._id });
                }
            } catch (cleanupError) {
                console.error('Cleanup failed during verification error:', cleanupError.message);
            }

            res.status(500).json({ message: 'Server error during email verification' });
        }
    }),
];

export const login = [
    setSecurityHeaders,
    validate([
        body('usernameOrEmail').notEmpty().withMessage('Username or email is required please'),
        body('password').optional().notEmpty().withMessage('Password is required please'),
        body('fingerprint').custom((value) => DEV_MODE || value).withMessage('Device fingerprint is required'),
    ]),
    asyncHandler(async (req, res) => {
        const { usernameOrEmail, password, fingerprint } = req.body;
        const { ip, country, deviceInfo } = getClientInfo(req);

        console.info('Login route accessed', {
            body: { usernameOrEmail, fingerprint, password: password ? '[REDACTED]' : undefined },
            ip,
            country,
            deviceInfo,
            timestamp: new Date().toISOString(),
        });

        try {
            const user = await Users.findOne({
                $or: [
                    { email: { $regex: `^${usernameOrEmail}$`, $options: 'i' } },
                    { username: { $regex: `^${usernameOrEmail}$`, $options: 'i' } },
                ],
            });

            // User doesn't exist - should sign up first
            if (!user) {
                console.warn('User not found', { usernameOrEmail, ip, country, deviceInfo });
                return res.status(400).json({
                    success: false,
                    message: 'Account not found. Please sign up first.',
                    action: 'signup'
                });
            }

            // User exists but email not verified - resend verification code
            if (!user.isActive) {
                console.warn('Email not verified', { usernameOrEmail, ip, country, deviceInfo });

                const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
                user.emailVerifyToken = verificationCode;
                user.emailVerifyExpires = new Date(Date.now() + 15 * 60 * 1000);
                await user.save();

                const emailSent = await sendEmailData('email_verification', user.email, {
                    username: user.username,
                    verificationCode: verificationCode,
                    supportEmail: 'support@quantumrobots.com'
                });

                if (!emailSent) {
                    console.error('Failed to send verification email during login', { email: user.email, ip, country, deviceInfo });
                    return res.status(500).json({
                        success: false,
                        message: 'Failed to send verification email'
                    });
                }

                return res.status(400).json({
                    success: false,
                    message: 'Please verify your email to continue.',
                    requiresEmailVerification: true,
                    email: user.email
                });
            }

            // Check password for verified user
            if (password && !(await user.verifyPassword(password))) {
                console.warn('Invalid password', { usernameOrEmail, ip, country, deviceInfo });
                return res.status(400).json({
                    success: false,
                    message: 'Invalid credentials'
                });
            }

            // Check device verification FIRST (before TOTP)
            const isDeviceVerified = user.isDeviceVerified(fingerprint);

            if (!isDeviceVerified && !DEV_MODE) {
                console.info('New device detected', { userId: user._id, fingerprint, ip, country, deviceInfo });

                const verificationCode = await user.addOrUpdateDeviceVerification(fingerprint, deviceInfo, ip, country);

                const emailSent = await sendEmailData('device_verification', user.email, {
                    username: user.username,
                    deviceInfo: deviceInfo,
                    ip: ip,
                    country: country,
                    timestamp: new Date().toISOString(),
                    verificationCode: verificationCode,
                    supportEmail: 'support@quantumrobots.com'
                });

                if (!emailSent) {
                    console.error('Failed to send device verification email', { email: user.email, ip, country, deviceInfo });
                    return res.status(500).json({
                        success: false,
                        message: 'Failed to send verification email'
                    });
                }

                console.info('Device verification code sent', {
                    userId: user._id,
                    fingerprint,
                    ip,
                    country,
                    deviceInfo,
                });

                return res.status(200).json({
                    success: false,
                    message: 'New device detected. Please check your email for the verification code.',
                    requiresDeviceVerification: true,
                    fingerprint: fingerprint
                });
            }

            // Handle TOTP logic AFTER device verification
            if (user.twoFactorEnabled && !DEV_MODE) {
                // TOTP is enabled but not setup (pending setup from signup)
                if (!user.twoFactorSetupCompleted) {
                    console.info('TOTP enabled but not setup - requiring setup', {
                        userId: user._id,
                        ip,
                        country,
                        deviceInfo
                    });

                    return res.status(200).json({
                        success: false,
                        message: 'TOTP setup required. Please complete TOTP setup to continue.',
                        requiresTOTPSetup: true,
                        usernameOrEmail: usernameOrEmail
                    });
                }

                // TOTP is enabled and setup - require TOTP code in separate verification step
                console.info('TOTP enabled and setup - requiring verification', {
                    userId: user._id,
                    ip,
                    country,
                    deviceInfo
                });

                return res.status(200).json({
                    success: false,
                    message: 'TOTP code required for login',
                    requiresTOTPVerification: true,
                    usernameOrEmail: usernameOrEmail
                });
            }

            // Successful login - all checks passed (no TOTP required or TOTP not enabled)
            user.lastLogin = new Date();
            user.lastLoginIp = ip;
            user.lastLoginDevice = deviceInfo;
            await user.cleanSessions();

            const accessToken = await user.generateAccessToken();
            const refreshToken = await user.generateRefreshToken(fingerprint || 'dev-mode', ip, country, deviceInfo);

            await user.save();

            console.info('Login successful', {
                userId: user._id,
                username: user.username,
                ip,
                country,
                deviceInfo
            });

            return res.json({
                success: true,
                accessToken,
                refreshToken,
                csrfToken: user.sessions[user.sessions.length - 1].csrfToken,
                user: sanitizeUser(user),
                message: 'Login successful'
            });
        } catch (error) {
            console.error('Login error', {
                error: error.message,
                stack: error.stack,
                usernameOrEmail,
                ip,
                country,
                deviceInfo,
                timestamp: new Date().toISOString(),
            });
            return res.status(500).json({
                success: false,
                message: 'Server error during login'
            });
        }
    }),
];

export const verifyDeviceCode = [
    setSecurityHeaders,
    validate([
        body('verificationCode').isLength({ min: 6, max: 6 }).withMessage('Verification code must be 6 digits'),
        body('fingerprint').notEmpty().withMessage('Device fingerprint is required'),
        body('usernameOrEmail').notEmpty().withMessage('Username or email is required'),
    ]),
    asyncHandler(async (req, res) => {
        const { verificationCode, fingerprint, usernameOrEmail } = req.body;
        const { ip, country, deviceInfo } = getClientInfo(req);

        console.info('Verify device code route accessed', {
            body: { usernameOrEmail, fingerprint, verificationCode: '[REDACTED]' },
            ip,
            country,
            deviceInfo,
            timestamp: new Date().toISOString(),
        });

        try {
            const user = await Users.findOne({
                $or: [
                    { email: { $regex: `^${usernameOrEmail}$`, $options: 'i' } },
                    { username: { $regex: `^${usernameOrEmail}$`, $options: 'i' } },
                ],
            });

            if (!user) {
                console.warn('User not found for device verification', { usernameOrEmail, ip, country, deviceInfo });
                return res.status(404).json({ message: 'User not found' });
            }

            const isVerified = await user.verifyDeviceCode(fingerprint, verificationCode);

            if (!isVerified) {
                console.warn('Invalid or expired verification code', {
                    usernameOrEmail,
                    fingerprint,
                    ip,
                    country,
                    deviceInfo
                });
                return res.status(400).json({ message: 'Invalid or expired verification code' });
            }

            user.lastLogin = new Date();
            user.lastLoginIp = ip;
            user.lastLoginDevice = deviceInfo;
            await user.cleanSessions();

            const accessToken = await user.generateAccessToken();
            const refreshToken = await user.generateRefreshToken(fingerprint, ip, country, deviceInfo);

            await user.save();

            console.info('Device verified and login successful', {
                userId: user._id,
                username: user.username,
                fingerprint,
                ip,
                country,
                deviceInfo
            });

            return res.json({
                accessToken,
                refreshToken,
                csrfToken: user.sessions[user.sessions.length - 1].csrfToken,
                user: sanitizeUser(user),
                message: 'Device verified successfully!'
            });
        } catch (error) {
            console.error('Verify device code error', {
                error: error.message,
                stack: error.stack,
                usernameOrEmail,
                ip,
                country,
                deviceInfo,
                timestamp: new Date().toISOString(),
            });
            return res.status(500).json({ message: 'Server error during device verification' });
        }
    }),
];

export const refreshToken = [
    setSecurityHeaders,
    validateCsrfToken,
    validate([
        body('refreshToken').notEmpty().withMessage('Refresh token is required'),
        body('fingerprint').custom((value) => DEV_MODE || value).withMessage('Device fingerprint is required'),
    ]),
    asyncHandler(async (req, res) => {
        const { refreshToken, fingerprint } = req.body;
        const csrfToken = req.headers['x-csrf-token'];
        const { ip, country, deviceInfo } = getClientInfo(req);

        console.info('Refresh token route accessed', {
            body: { fingerprint, refreshToken: '[REDACTED]', csrfToken: csrfToken ? '[REDACTED]' : undefined },
            ip,
            country,
            deviceInfo,
            timestamp: new Date().toISOString(),
        });

        try {
            if (await isBlacklisted(refreshToken)) {
                console.warn('Blacklisted refresh token', { ip, country, deviceInfo });
                return res.status(401).json({ message: 'Invalid refresh token' });
            }

            const payload = jwt.verify(refreshToken, publicKey, {
                algorithms: ['RS256'],
                issuer: ISSUER,
                audience: AUDIENCE,
            });
            const user = await Users.findById(payload.userId);
            if (!user) {
                console.warn('User not found for refresh token', { userId: payload.userId, ip, country, deviceInfo });
                return res.status(404).json({ message: 'User not found' });
            }

            const sessionIndex = user.sessions.findIndex((s) => s.token === refreshToken && s.csrfToken === csrfToken);
            if (sessionIndex === -1) {
                console.warn('Invalid refresh token or CSRF token', {
                    userId: user._id,
                    ip,
                    country,
                    deviceInfo,
                });
                return res.status(401).json({ message: 'Invalid refresh token or CSRF token' });
            }
            const session = user.sessions[sessionIndex];

            if (!DEV_MODE && fingerprint && session.fingerprint !== fingerprint) {
                if (!user.isDeviceVerified(fingerprint)) {
                    console.warn('Unverified device during refresh', { userId: user._id, ip, country, deviceInfo });
                    return res.status(401).json({ message: 'Unverified device detected. Please log in again.' });
                }
            }

            if (session.used) {
                user.sessions = [];
                await user.save();
                console.warn('Token reuse detected, sessions cleared', { userId: user._id, ip, country, deviceInfo });
                return res.status(401).json({ message: 'Token reuse detected - all sessions invalidated' });
            }

            user.sessions[sessionIndex].used = true;
            const newRefresh = await user.generateRefreshToken(fingerprint || session.fingerprint, ip, country, deviceInfo);
            await user.cleanSessions();
            await user.save();

            const newAccess = await user.generateAccessToken();
            console.info('Refresh token rotated successfully', { userId: user._id, ip, country, deviceInfo });

            res.json({
                accessToken: newAccess,
                refreshToken: newRefresh,
                csrfToken: user.sessions[user.sessions.length - 1].csrfToken,
            });
        } catch (error) {
            console.error('Refresh token error', {
                error: error.message,
                stack: error.stack,
                ip,
                country,
                deviceInfo,
                timestamp: new Date().toISOString(),
            });
            return res.status(401).json({ message: 'Invalid refresh token' });
        }
    }),
];

export const logout = [
    setSecurityHeaders,
    validate([body('refreshToken').notEmpty().withMessage('Refresh token is required')]),
    asyncHandler(async (req, res) => {
        const { refreshToken } = req.body;
        const csrfToken = req.headers['x-csrf-token'];
        const { ip, country, deviceInfo } = getClientInfo(req);

        console.info('Logout route accessed', {
            body: { refreshToken: '[REDACTED]', csrfToken: csrfToken ? '[REDACTED]' : undefined },
            ip,
            country,
            deviceInfo,
            timestamp: new Date().toISOString(),
        });

        try {
            const payload = jwt.verify(refreshToken, publicKey, { algorithms: ['RS256'] });
            const user = await Users.findById(payload.userId);
            if (!user) {
                console.warn('User not found for logout', { userId: payload.userId, ip, country, deviceInfo });
                return res.status(401).json({ message: 'Invalid refresh token' });
            }

            const sessionIndex = user.sessions.findIndex((s) => s.token === refreshToken && (!csrfToken || s.csrfToken === csrfToken));
            if (sessionIndex === -1) {
                console.warn('Invalid refresh token or CSRF token', {
                    userId: user._id,
                    ip,
                    country,
                    deviceInfo,
                });
                return res.status(401).json({ message: 'Invalid refresh token or CSRF token' });
            }

            user.sessions = user.sessions.filter((s) => s.token !== refreshToken);
            await blacklistToken(refreshToken);
            await user.save();
            console.info('User logged out successfully', { userId: user._id, ip, country, deviceInfo });
            res.json({ message: 'Logged out successfully' });
        } catch (error) {
            console.error('Logout error', {
                error: error.message,
                stack: error.stack,
                ip,
                country,
                deviceInfo,
                timestamp: new Date().toISOString(),
            });
            return res.status(401).json({ message: 'Invalid refresh token' });
        }
    }),
];

export const requestPasswordReset = [
    setSecurityHeaders,
    validate([body('email').isEmail().withMessage('Invalid email format')]),
    asyncHandler(async (req, res) => {
        const { email } = req.body;
        const { ip, country, deviceInfo } = getClientInfo(req);

        console.info('Request password reset accessed', {
            body: { email },
            ip,
            country,
            deviceInfo,
            timestamp: new Date().toISOString(),
        });

        try {
            const user = await Users.findOne({ email });
            if (!user) {
                console.warn('User not found for password reset', { email, ip, country, deviceInfo });
                return res.status(404).json({ message: 'User not found' });
            }
            if (!user.isActive) {
                console.warn('Email not verified for password reset', { email, ip, country, deviceInfo });
                return res.status(401).json({ message: 'Email not verified' });
            }

            const resetToken = await user.generatePasswordResetToken();
            await user.save();

            const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;

            // Send password reset email data
            const emailSent = await sendEmailData('password_reset', email, {
                username: user.username,
                resetLink: resetUrl,
                token: resetToken,
                supportEmail: 'support@quantumrobots.com'
            });

            if (!emailSent) {
                console.error('Failed to send password reset email via external service', { email, ip, country, deviceInfo });
                return res.status(500).json({ message: 'Failed to send password reset email' });
            }

            console.info('Password reset email sent', { email, ip, country, deviceInfo });
            res.json({ message: 'Password reset email sent. Please check your inbox.' });
        } catch (error) {
            console.error('Request password reset error', {
                error: error.message,
                stack: error.stack,
                email,
                ip,
                country,
                deviceInfo,
                timestamp: new Date().toISOString(),
            });
            res.status(500).json({ message: 'Server error during password reset request' });
        }
    }),
];

export const resetPassword = [
    setSecurityHeaders,
    validate([
        query('token').notEmpty().withMessage('Reset token is required'),
        body('newPassword')
            .matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/)
            .withMessage('Password must be at least 8 characters, include a letter, number, and special character'),
        body('confirmPassword')
            .custom((value, { req }) => value === req.body.newPassword)
            .withMessage('Passwords do not match'),
    ]),
    asyncHandler(async (req, res) => {
        const { token } = req.query;
        const { newPassword } = req.body;
        const { ip, country, deviceInfo } = getClientInfo(req);

        console.info('Reset password route accessed', {
            body: { newPassword: '[REDACTED]', confirmPassword: '[REDACTED]' },
            ip,
            country,
            deviceInfo,
            timestamp: new Date().toISOString(),
        });

        try {
            const user = await Users.findOne({
                passwordResetToken: token,
                passwordResetExpires: { $gt: Date.now() },
            });
            if (!user) {
                console.warn('Invalid or expired reset token', { ip, country, deviceInfo });
                return res.status(400).json({ message: 'Invalid or expired reset token' });
            }

            const isSamePassword = await bcrypt.compare(newPassword, user.password);
            if (isSamePassword) {
                console.warn('New password same as old', { userId: user._id, ip, country, deviceInfo });
                return res.status(400).json({ message: 'New password cannot be the same as the old password' });
            }

            user.password = newPassword;
            user.passwordResetToken = undefined;
            user.passwordResetExpires = undefined;
            await user.save();

            console.info('Password reset successfully', { userId: user._id, email: user.email, ip, country, deviceInfo });
            res.json({ message: 'Password reset successful! You can now log in with your new password.' });
        } catch (error) {
            console.error('Reset password error', {
                error: error.message,
                stack: error.stack,
                ip,
                country,
                deviceInfo,
                timestamp: new Date().toISOString(),
            });
            return res.status(500).json({ message: 'Server error during password reset' });
        }
    }),
];

export const verifyResetToken = [
    setSecurityHeaders,
    validate([query('token').notEmpty().withMessage('Reset token is required')]),
    asyncHandler(async (req, res) => {
        const { token } = req.query;
        const { ip, country, deviceInfo } = getClientInfo(req);

        console.info('Verify reset token route accessed', {
            query: { token: '[REDACTED]' },
            ip,
            country,
            deviceInfo,
            timestamp: new Date().toISOString(),
        });

        try {
            const user = await Users.findOne({
                passwordResetToken: token,
                passwordResetExpires: { $gt: Date.now() },
            });
            if (!user) {
                console.warn('Invalid or expired reset token', { ip, country, deviceInfo });
                return res.status(400).json({ message: 'Invalid or expired reset token' });
            }
            console.info('Reset token verified', { userId: user._id, email: user.email, ip, country, deviceInfo });
            res.status(200).json({ message: 'Reset token is valid' });
        } catch (error) {
            console.error('Verify reset token error', {
                error: error.message,
                stack: error.stack,
                ip,
                country,
                deviceInfo,
                timestamp: new Date().toISOString(),
            });
            return res.status(500).json({ message: 'Server error during token verification' });
        }
    }),
];

export const updateProfileImage = [
    setSecurityHeaders,
    validate([body('image').notEmpty().withMessage('Image is required')]),
    asyncHandler(async (req, res) => {
        const { image } = req.body;
        const userId = req.user?.id;
        const { ip, country, deviceInfo } = getClientInfo(req);

        console.info('Update profile image route accessed', {
            userId,
            ip,
            country,
            deviceInfo,
            timestamp: new Date().toISOString(),
        });

        try {
            const user = await Users.findById(userId);
            if (!user) {
                console.warn('User not found for profile image update', { userId, ip, country, deviceInfo });
                return res.status(404).json({ message: 'User not found' });
            }
            if (!user.isActive) {
                console.warn('Email not verified for profile image update', { userId, ip, country, deviceInfo });
                return res.status(403).json({ message: 'Only verified users can update profile image' });
            }

            const uploaded = await cloudinary.uploader.upload(image, {
                folder: 'profile_images',
                public_id: `user_${user._id}_${Date.now()}`,
                overwrite: true,
                resource_type: 'auto',
            });

            user.profileImage = uploaded.secure_url;
            await user.save();

            console.info('Profile image updated successfully', { userId, email: user.email, ip, country, deviceInfo });
            res.status(200).json({
                message: 'Profile image updated successfully',
                profileImage: user.profileImage,
            });
        } catch (error) {
            console.error('Update profile image error', {
                error: error.message,
                stack: error.stack,
                userId,
                ip,
                country,
                deviceInfo,
                timestamp: new Date().toISOString(),
            });
            return res.status(500).json({ message: 'Server error during profile image update' });
        }
    }),
];

export const updateUsername = [
    setSecurityHeaders,
    validate([
        body('newUsername')
            .matches(/^[a-zA-Z0-9_-]{3,}$/)
            .withMessage('Username must be at least 3 characters, alphanumeric, underscores, or hyphens'),
    ]),
    asyncHandler(async (req, res) => {
        const { newUsername } = req.body;
        const userId = req.user?.id;
        const { ip, country, deviceInfo } = getClientInfo(req);

        console.info('Update username route accessed', {
            body: { newUsername },
            userId,
            ip,
            country,
            deviceInfo,
            timestamp: new Date().toISOString(),
        });

        try {
            const user = await Users.findById(userId);
            if (!user) {
                console.warn('User not found for username update', { userId, ip, country, deviceInfo });
                return res.status(404).json({ message: 'User not found' });
            }
            if (!user.isActive) {
                console.warn('Email not verified for username update', { userId, ip, country, deviceInfo });
                return res.status(403).json({ message: 'Only verified users can update username' });
            }

            const existing = await Users.findOne({ username: newUsername });
            if (existing) {
                console.warn('Username already taken', { userId, newUsername, ip, country, deviceInfo });
                return res.status(400).json({ message: 'Username already taken' });
            }

            user.username = newUsername;
            await user.save();

            console.info('Username updated successfully', { userId, username: newUsername, ip, country, deviceInfo });
            res.status(200).json({
                message: 'Username updated successfully',
                username: user.username,
            });
        } catch (error) {
            console.error('Update username error', {
                error: error.message,
                stack: error.stack,
                userId,
                ip,
                country,
                deviceInfo,
                timestamp: new Date().toISOString(),
            });
            return res.status(500).json({ message: 'Server error during username update' });
        }
    }),
];

export const getProfile = [
    setSecurityHeaders,
    asyncHandler(async (req, res) => {
        const { ip, country, deviceInfo } = getClientInfo(req);

        console.info('Get profile route accessed', {
            userId: req.user.id,
            ip,
            country,
            deviceInfo,
            timestamp: new Date().toISOString(),
        });

        try {
            const user = await Users.findById(req.user.id);
            if (!user) {
                console.warn('User not found for profile fetch', { userId: req.user.id, ip, country, deviceInfo });
                return res.status(404).json({ message: 'User not found' });
            }

            console.info('Profile fetched successfully', { userId: user._id, email: user.email, ip, country, deviceInfo });
            res.status(200).json({
                message: 'Profile fetched successfully',
                user: sanitizeUser(user),
            });
        } catch (error) {
            console.error('Get profile error', {
                error: error.message,
                stack: error.stack,
                userId: req.user.id,
                ip,
                country,
                deviceInfo,
                timestamp: new Date().toISOString(),
            });
            return res.status(500).json({ message: 'Server error during profile fetch' });
        }
    }),
];

export const getAdminDashboard = [
    setSecurityHeaders,
    asyncHandler(async (req, res) => {
        const { ip, country, deviceInfo } = getClientInfo(req);

        console.info('Admin dashboard accessed', {
            userId: req.user.id,
            email: req.user.email,
            ip,
            country,
            deviceInfo,
            timestamp: new Date().toISOString(),
        });

        try {
            const users = await Users.find().select('username email role isActive createdAt');
            console.info('Admin dashboard fetched successfully', { userId: req.user.id, ip, country, deviceInfo });
            res.status(200).json({
                message: `Admin access granted for ${req.user.email}`,
                totalUsers: users.length,
                users,
            });
        } catch (error) {
            console.error('Admin dashboard error', {
                error: error.message,
                stack: error.stack,
                userId: req.user.id,
                ip,
                country,
                deviceInfo,
                timestamp: new Date().toISOString(),
            });
            return res.status(500).json({ message: 'Server error during admin dashboard fetch' });
        }
    }),
];

export const cleanupExpiredData = asyncHandler(async (req, res) => {
    try {
        const now = new Date();

        const usersWithExpiredDevices = await Users.updateMany(
            {
                isActive: true,
                'devices': {
                    $elemMatch: {
                        status: 'NOT CONFIRMED',
                        expiresAt: { $lt: now }
                    }
                }
            },
            {
                $pull: {
                    devices: {
                        status: 'NOT CONFIRMED',
                        expiresAt: { $lt: now }
                    }
                }
            }
        );

        console.info('Cleanup completed', {
            cleanedUsers: usersWithExpiredDevices.modifiedCount,
            timestamp: now.toISOString()
        });

        res.json({
            message: 'Cleanup completed successfully',
            cleanedDevices: usersWithExpiredDevices.modifiedCount
        });
    } catch (error) {
        console.error('Cleanup error', {
            error: error.message,
            stack: error.stack,
            timestamp: new Date().toISOString(),
        });
        res.status(500).json({ message: 'Server error during cleanup' });
    }
});