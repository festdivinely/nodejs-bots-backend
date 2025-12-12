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
const DEV_MODE = process.env.DEV_MODE === 'true';
const EMAIL_SERVICE_DOMAIN = process.env.EMAIL_SERVICE_DOMAIN || 'https://choir-song-project-typing-1e66.vercel.app';
const redis = process.env.REDIS_URL ? new Redis(process.env.REDIS_URL) : null;

// DEBUG: Log what we're getting from environment
console.log('🔑 Key Loading Debug:', {
    envPrivateKeyExists: !!process.env.PRIVATE_KEY,
    envPublicKeyExists: !!process.env.PUBLIC_KEY,
    envPrivateKeyLength: process.env.PRIVATE_KEY?.length,
    envPublicKeyLength: process.env.PUBLIC_KEY?.length,
    envPrivateKeyFirst100: process.env.PRIVATE_KEY?.substring(0, 100),
    envPublicKeyFirst100: process.env.PUBLIC_KEY?.substring(0, 100)
});

let privateKey, publicKey;

try {
    // Decode from base64
    privateKey = Buffer.from(process.env.PRIVATE_KEY || '', 'base64').toString('utf-8');
    publicKey = Buffer.from(process.env.PUBLIC_KEY || '', 'base64').toString('utf-8');

    console.log('🔑 Key Decode Debug:', {
        privateKeyLength: privateKey?.length,
        publicKeyLength: publicKey?.length,
        privateKeyStartsWith: privateKey?.substring(0, 50),
        publicKeyStartsWith: publicKey?.substring(0, 50),
        privateKeyEndsWith: privateKey?.substring(Math.max(0, privateKey?.length - 50)),
        publicKeyEndsWith: publicKey?.substring(Math.max(0, publicKey?.length - 50)),
        privateKeyContainsBegin: privateKey?.includes('BEGIN PRIVATE KEY'),
        publicKeyContainsBegin: publicKey?.includes('BEGIN PUBLIC KEY')
    });

    // Test the keys work
    const testToken = jwt.sign({ test: 'test' }, privateKey, {
        algorithm: 'RS256',
        issuer: ISSUER,
        audience: AUDIENCE
    });

    jwt.verify(testToken, publicKey, {
        algorithms: ['RS256'],
        issuer: ISSUER,
        audience: AUDIENCE
    });

    console.log('✅ JWT Key Test: SUCCESS - Keys are working correctly');

} catch (keyError) {
    console.error('❌ JWT Key Test: FAILED', keyError.message);
    console.error('Key error details:', {
        name: keyError.name,
        message: keyError.message,
        stack: keyError.stack
    });

    // For development, we'll continue but log a warning
    if (DEV_MODE) {
        console.warn('⚠️ DEV_MODE: Continuing despite JWT key error');
    } else {
        throw new Error(`JWT key configuration error: ${keyError.message}`);
    }
}

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

// In your backend authController.js, update the register function
export const register = [
    setSecurityHeaders,
    validate([
        ...usernameValidation,
        body('email').isEmail().withMessage('Invalid email format'),
        ...passwordValidation,
        body('fingerprint').custom((value) => DEV_MODE || value).withMessage('Device fingerprint is required'),
    ]),
    asyncHandler(async (req, res) => {
        const { username, email, password, fingerprint, enableTOTP, deviceInfo, ipAddress, country } = req.body;
        const backendClientInfo = getClientInfo(req); // This gets IP, country from request

        console.info('🔵 BACKEND - REGISTRATION REQUEST DETAILS:', {
            timestamp: new Date().toISOString(),
            userData: {
                username,
                email,
                enableTOTP: enableTOTP || false,
                fingerprint
            },
            deviceInfoFromFrontend: deviceInfo || 'Not provided',
            ipAddressFromFrontend: ipAddress || 'Not provided',
            countryFromFrontend: country || 'Not provided',
            backendDetectedInfo: {
                ip: backendClientInfo.ip,
                country: backendClientInfo.country,
                deviceInfo: backendClientInfo.deviceInfo
            },
            headers: {
                'user-agent': req.headers['user-agent'],
                'x-forwarded-for': req.headers['x-forwarded-for']
            }
        });

        try {
            const existingUser = await Users.findOne({ $or: [{ email }, { username }] });

            // User exists but is NOT verified - resend verification code
            if (existingUser && !existingUser.isActive) {
                console.info('🟡 Unverified user attempting to register again', {
                    email,
                    username,
                    ip: backendClientInfo.ip,
                    country: backendClientInfo.country,
                    deviceInfo: backendClientInfo.deviceInfo
                });

                // GENERATE 6-DIGIT CODE (not token)
                const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
                existingUser.emailVerifyCode = verificationCode;
                existingUser.emailVerifyCodeExpires = new Date(Date.now() + 15 * 60 * 1000);

                if (enableTOTP) {
                    existingUser.twoFactorEnabled = true;
                    existingUser.twoFactorSetupCompleted = false;
                    existingUser.pendingTOTPEnable = true;
                }

                await existingUser.save();

                // Send verification email with CODE
                const emailSent = await sendEmailData('email_verification', email, {
                    username: existingUser.username,
                    verificationCode: verificationCode, // 6-digit code
                    supportEmail: 'support@quantumrobots.com'
                });

                if (!emailSent) {
                    console.error('❌ Failed to resend verification email', {
                        email,
                        ip: backendClientInfo.ip,
                        country: backendClientInfo.country,
                        deviceInfo: backendClientInfo.deviceInfo
                    });
                    return res.status(500).json({ message: 'Failed to send verification email' });
                }

                // ✅ FIXED: Added requiresTOTPSetup to response
                return res.status(200).json({
                    success: true,
                    message: 'Verification code resent to your email.',
                    requiresEmailVerification: true,
                    email: email,
                    requiresTOTPSetup: enableTOTP || false, // ← THIS IS THE FIX
                    pendingTOTPEnable: enableTOTP || false
                });
            }

            // User exists and IS verified - cannot register again
            if (existingUser) {
                console.warn('🔴 Verified user already exists', {
                    email,
                    username,
                    ip: backendClientInfo.ip,
                    country: backendClientInfo.country,
                    deviceInfo: backendClientInfo.deviceInfo
                });
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
                pendingTOTPEnable: enableTOTP || false
            });

            // GENERATE 6-DIGIT CODE (not token)
            const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
            user.emailVerifyCode = verificationCode;
            user.emailVerifyCodeExpires = new Date(Date.now() + 15 * 60 * 1000);

            // ✅ DEVICE IS NOW CREATED WITH THE FINGERPRINT FROM FRONTEND
            user.devices.push({
                fingerprint: fingerprint,
                status: 'NOT CONFIRMED',
                deviceInfo: deviceInfo ? JSON.stringify(deviceInfo) : backendClientInfo.deviceInfo,
                ip: backendClientInfo.ip, // Use backend detected IP
                country: backendClientInfo.country, // Use backend detected country
                createdAt: new Date(),
                expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
            });

            await user.save();

            console.info('🟢 New user created:', {
                userId: user._id,
                username,
                email,
                deviceInfo: deviceInfo || backendClientInfo.deviceInfo,
                ip: backendClientInfo.ip,
                country: backendClientInfo.country
            });

            // Send verification email with CODE
            const emailSent = await sendEmailData('email_verification', email, {
                username: username,
                verificationCode: verificationCode, // 6-digit code
                supportEmail: 'support@quantumrobots.com'
            });

            if (!emailSent) {
                console.error('❌ Failed to send verification email via external service', {
                    email,
                    ip: backendClientInfo.ip,
                    country: backendClientInfo.country,
                    deviceInfo: backendClientInfo.deviceInfo
                });
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
                pendingTOTPEnable: enableTOTP || false,
                requiresTOTPSetup: enableTOTP || false
            });
        } catch (error) {
            console.error('🔴 Registration error', {
                error: error.message,
                stack: error.stack,
                email,
                ip: backendClientInfo.ip,
                country: backendClientInfo.country,
                deviceInfo: backendClientInfo.deviceInfo,
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

/// Add this to authController.js

// For TOTP Setup During Login (when user registered with enableTOTP but hasn't completed setup)
export const setupTOTPLogin = [
    validate([
        body('usernameOrEmail').notEmpty().withMessage('Username or email is required'),
        body('fingerprint').custom((value) => DEV_MODE || value).withMessage('Device fingerprint is required'),
    ]),
    asyncHandler(async (req, res) => {
        const { usernameOrEmail, fingerprint } = req.body;
        const { ip, country, deviceInfo } = getClientInfo(req);

        console.info('Setup TOTP during login route accessed', {
            body: { usernameOrEmail, fingerprint },
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
                isActive: true,
                pendingTOTPEnable: true, // User registered with TOTP but hasn't completed setup
                twoFactorSetupCompleted: false
            });

            if (!user) {
                console.warn('User not found or TOTP setup not required', {
                    usernameOrEmail,
                    ip,
                    country,
                    deviceInfo
                });
                return res.status(400).json({
                    success: false,
                    message: 'User not found or TOTP setup not required'
                });
            }

            // Check device verification first
            const isDeviceVerified = user.isDeviceVerified(fingerprint);

            if (!isDeviceVerified && !DEV_MODE) {
                console.info('New device detected during TOTP setup', {
                    userId: user._id,
                    fingerprint,
                    ip,
                    country,
                    deviceInfo
                });

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
                    console.error('Failed to send device verification email', {
                        email: user.email,
                        ip,
                        country,
                        deviceInfo
                    });
                    return res.status(500).json({
                        success: false,
                        message: 'Failed to send verification email'
                    });
                }

                return res.status(200).json({
                    success: false,
                    message: 'New device detected. Please verify device first.',
                    requiresDeviceVerification: true,
                    fingerprint: fingerprint
                });
            }

            // Generate new secret for TOTP setup
            const secret = speakeasy.generateSecret({
                name: `QuantumRobots:${user.email}`,
                issuer: 'Quantum Robots'
            });

            // Store temporary secret
            user.twoFactorSecret = secret.base32;
            await user.save();

            console.info('TOTP setup secret generated during login', {
                userId: user._id,
                username: user.username,
                ip,
                country,
                deviceInfo
            });

            return res.json({
                success: true,
                secret: secret.base32,
                message: 'Enter this code manually in Google Authenticator to complete TOTP setup'
            });

        } catch (error) {
            console.error('TOTP setup during login error:', {
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
                message: 'Server error during TOTP setup'
            });
        }
    })
];

// For IN-APP setup (user already logged in)
// For IN-APP setup (user already logged in)
// For IN-APP setup (user already logged in)
export const verifyTOTPSetup = [
    validate([
        body('totpCode').isLength({ min: 6, max: 6 }).withMessage('TOTP code must be 6 digits'),
    ]),
    asyncHandler(async (req, res) => {
        const { totpCode } = req.body;
        const { ip, country, deviceInfo } = getClientInfo(req);

        console.info('Verify TOTP setup in-app route accessed', {
            userId: req.user.id,
            totpCode: '[REDACTED]',
            ip,
            country,
            deviceInfo,
            timestamp: new Date().toISOString(),
        });

        try {
            const user = await Users.findById(req.user.id);

            if (!user || !user.twoFactorSecret) {
                console.error('TOTP verification failed - User or secret not found:', {
                    userId: req.user.id,
                    hasUser: !!user,
                    hasSecret: user?.twoFactorSecret ? 'Yes' : 'No',
                    pendingTOTPEnable: user?.pendingTOTPEnable,
                    twoFactorSetupCompleted: user?.twoFactorSetupCompleted
                });
                return res.status(400).json({
                    success: false,
                    message: 'TOTP not setup properly'
                });
            }

            // Verify TOTP code with increased window for time drift
            const verified = speakeasy.totp.verify({
                secret: user.twoFactorSecret,
                encoding: 'base32',
                token: totpCode,
                window: 10 // Allows ±300 seconds (5 minutes) time drift
            });

            if (!verified) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid TOTP code. Please ensure your device time is synchronized.'
                });
            }

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
            user.pendingTOTPEnable = false;

            await user.save();

            console.info('TOTP setup completed in-app', {
                userId: user._id,
                username: user.username,
                email: user.email,
                ip,
                country,
                deviceInfo,
                backupCodesCount: backupCodes.length,
                twoFactorEnabled: true
            });

            // ✅ SEND BACKUP CODES VIA EMAIL
            const emailSent = await sendEmailData('backup_codes', user.email, {
                username: user.username,
                backupCodes: backupCodes,
                supportEmail: 'support@quantumrobots.com'
            });

            if (!emailSent) {
                console.error('Failed to send backup codes email', {
                    email: user.email,
                    ip,
                    country,
                    deviceInfo
                });
                // Still return success but log the email failure
                console.warn('Backup codes email failed to send, but TOTP setup was successful');
            } else {
                console.info('Backup codes email sent successfully', {
                    email: user.email,
                    backupCodesCount: backupCodes.length
                });
            }

            return res.json({
                success: true,
                message: 'TOTP setup completed successfully! Backup codes have been sent to your email.',
                twoFactorEnabled: true
                // ❌ NO BACKUP CODES IN RESPONSE - they're sent via email
            });

        } catch (error) {
            console.error('TOTP setup verification error (in-app):', {
                error: error.message,
                stack: error.stack,
                userId: req.user.id,
                ip,
                country,
                deviceInfo,
                timestamp: new Date().toISOString(),
            });
            return res.status(500).json({
                success: false,
                message: 'Failed to verify TOTP setup'
            });
        }
    })
];

// For LOGIN setup (user completing TOTP during login)
// For LOGIN setup (user completing TOTP during login)
export const verifyTOTPSetupLogin = [
    validate([
        body('totpCode').isLength({ min: 6, max: 6 }).withMessage('TOTP code must be 6 digits'),
        body('usernameOrEmail').notEmpty().withMessage('Username or email is required'),
        body('fingerprint').notEmpty().withMessage('Device fingerprint is required'),
    ]),
    asyncHandler(async (req, res) => {
        const { totpCode, usernameOrEmail, fingerprint } = req.body;
        const { ip, country, deviceInfo } = getClientInfo(req);

        console.info('Verify TOTP setup during login route accessed', {
            body: { usernameOrEmail, fingerprint, totpCode: '[REDACTED]' },
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
                isActive: true,
                pendingTOTPEnable: true,
                twoFactorSetupCompleted: false
            });

            if (!user || !user.twoFactorSecret) {
                console.error('TOTP verification failed - User or secret not found:', {
                    usernameOrEmail,
                    hasUser: !!user,
                    hasSecret: user?.twoFactorSecret ? 'Yes' : 'No',
                    pendingTOTPEnable: user?.pendingTOTPEnable,
                    twoFactorSetupCompleted: user?.twoFactorSetupCompleted
                });
                return res.status(400).json({
                    success: false,
                    message: 'TOTP not setup properly or user not found'
                });
            }

            // Verify TOTP code with increased window for time drift
            const verified = speakeasy.totp.verify({
                secret: user.twoFactorSecret,
                encoding: 'base32',
                token: totpCode,
                window: 10 // Allows ±300 seconds (5 minutes) time drift
            });

            if (!verified) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid TOTP code. Please ensure your device time is synchronized.'
                });
            }

            // Generate backup codes
            const backupCodes = Array.from({ length: 8 }, () =>
                Math.random().toString(36).substring(2, 10).toUpperCase()
            );

            // Hash backup codes
            const hashedBackupCodes = await Promise.all(
                backupCodes.map(async (code) => await bcrypt.hash(code, 10))
            );

            // Complete TOTP setup and login
            user.twoFactorEnabled = true;
            user.twoFactorSetupCompleted = true;
            user.twoFactorBackupCodes = hashedBackupCodes;
            user.pendingTOTPEnable = false;
            user.lastLogin = new Date();
            user.lastLoginIp = ip;
            user.lastLoginDevice = deviceInfo;

            await user.cleanSessions();

            const accessToken = await user.generateAccessToken();
            const refreshToken = await user.generateRefreshToken(fingerprint, ip, country, deviceInfo);

            await user.save();

            console.info('TOTP setup completed during login', {
                userId: user._id,
                username: user.username,
                email: user.email,
                ip,
                country,
                deviceInfo,
                backupCodesCount: backupCodes.length,
                twoFactorEnabled: true
            });

            // ✅ SEND BACKUP CODES VIA EMAIL
            const emailSent = await sendEmailData('backup_codes', user.email, {
                username: user.username,
                backupCodes: backupCodes,
                supportEmail: 'support@quantumrobots.com'
            });

            if (!emailSent) {
                console.error('Failed to send backup codes email', {
                    email: user.email,
                    ip,
                    country,
                    deviceInfo
                });
                // Still return success but log the email failure
                console.warn('Backup codes email failed to send, but TOTP setup was successful');
            } else {
                console.info('Backup codes email sent successfully', {
                    email: user.email,
                    backupCodesCount: backupCodes.length
                });
            }

            return res.json({
                success: true,
                message: 'TOTP setup completed and login successful! Backup codes have been sent to your email.',
                twoFactorEnabled: true,
                accessToken,
                refreshToken,
                csrfToken: user.sessions[user.sessions.length - 1].csrfToken,
                user: sanitizeUser(user)
                // ❌ NO BACKUP CODES IN RESPONSE - they're sent via email
            });

        } catch (error) {
            console.error('TOTP setup verification during login error:', {
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
                message: 'Failed to verify TOTP setup'
            });
        }
    })
];

// For verifying existing TOTP during login (user already has TOTP set up)
// For verifying existing TOTP during login (user already has TOTP set up)
export const verifyTOTPLogin = [
    validate([
        body('code').matches(/^([0-9]{6}|[A-Z0-9]{8})$/)
            .withMessage('Code must be either 6-digit TOTP code or 8-character backup code'),
        body('usernameOrEmail').notEmpty().withMessage('Username or email is required'),
        body('fingerprint').notEmpty().withMessage('Device fingerprint is required'),
    ]),
    asyncHandler(async (req, res) => {
        const { code, usernameOrEmail, fingerprint } = req.body;
        const { ip, country, deviceInfo } = getClientInfo(req);

        console.info('Verify TOTP during login route accessed', {
            body: { usernameOrEmail, fingerprint, code: '[REDACTED]' },
            ip,
            country,
            deviceInfo,
            timestamp: new Date().toISOString(),
        });

        try {
            // ✅ FIXED: Added +backupCodeLogs to the select to prevent undefined error
            const user = await Users.findOne({
                $or: [
                    { email: { $regex: `^${usernameOrEmail}$`, $options: 'i' } },
                    { username: { $regex: `^${usernameOrEmail}$`, $options: 'i' } },
                ],
                isActive: true,
                twoFactorEnabled: true,
                twoFactorSetupCompleted: true
            }).select('+twoFactorBackupCodes +backupCodeLogs'); // ✅ CRITICAL FIX: Added backupCodeLogs

            if (!user || !user.twoFactorSecret) {
                console.error('TOTP verification failed - User or secret not found:', {
                    usernameOrEmail,
                    hasUser: !!user,
                    hasSecret: user?.twoFactorSecret ? 'Yes' : 'No',
                    twoFactorEnabled: user?.twoFactorEnabled,
                    twoFactorSetupCompleted: user?.twoFactorSetupCompleted
                });
                return res.status(400).json({
                    success: false,
                    message: 'TOTP not properly configured'
                });
            }

            let isBackupCode = false;
            let verificationResult = null;
            let remainingBackupCodes = 0;

            // ✅ CHECK IF IT'S A BACKUP CODE (8 characters)
            if (code.length === 8) {
                isBackupCode = true;

                // Use model method to verify backup code
                verificationResult = await user.verifyBackupCode(code, ip, deviceInfo, country);

                if (!verificationResult.valid) {
                    return res.status(400).json({
                        success: false,
                        message: verificationResult.remainingCodes === 0
                            ? 'No backup codes available'
                            : 'Invalid backup code'
                    });
                }

                // Use model method to mark backup code as used
                remainingBackupCodes = await user.useBackupCode(
                    verificationResult.index,
                    ip,
                    deviceInfo,
                    country
                );

                console.info('Backup code used successfully', {
                    userId: user._id,
                    username: user.username,
                    remainingBackupCodes,
                    ip,
                    country,
                    deviceInfo
                });

                // ✅ SEND EMAIL NOTIFICATION FOR BACKUP CODE USAGE
                const emailSent = await sendEmailData('backup_code_used', user.email, {
                    username: user.username,
                    timestamp: new Date().toISOString(),
                    ip,
                    country,
                    deviceInfo,
                    remainingCodes: remainingBackupCodes,
                    action: 'Login with backup code',
                    supportEmail: 'support@quantumrobots.com'
                });

                if (!emailSent) {
                    console.error('Failed to send backup code usage notification email', {
                        email: user.email,
                        ip,
                        country,
                        deviceInfo
                    });
                    // Don't fail the login, just log it
                } else {
                    console.info('Backup code usage notification email sent', {
                        email: user.email,
                        remainingBackupCodes
                    });
                }
            }
            // ✅ CHECK IF IT'S A TOTP CODE (6 digits)
            else if (code.length === 6) {
                const verified = speakeasy.totp.verify({
                    secret: user.twoFactorSecret,
                    encoding: 'base32',
                    token: code,
                    window: 10 // Allow time drift
                });

                if (!verified) {
                    return res.status(400).json({
                        success: false,
                        message: 'Invalid TOTP code. Please try again.'
                    });
                }
            }

            // Complete login
            user.lastLogin = new Date();
            user.lastLoginIp = ip;
            user.lastLoginDevice = deviceInfo;
            await user.cleanSessions();

            const accessToken = await user.generateAccessToken();
            const refreshToken = await user.generateRefreshToken(fingerprint, ip, country, deviceInfo);

            await user.save();

            console.info('Login successful', {
                userId: user._id,
                username: user.username,
                method: isBackupCode ? 'backup_code' : 'totp_code',
                ip,
                country,
                deviceInfo,
                ...(isBackupCode && { remainingBackupCodes })
            });

            // ✅ RETURN DIFFERENT RESPONSE FOR BACKUP CODE USAGE
            if (isBackupCode) {
                return res.json({
                    success: true,
                    message: `Login successful! ${remainingBackupCodes} backup codes remaining.`,
                    backupCodesRemaining: remainingBackupCodes,
                    showWarning: remainingBackupCodes <= 3,
                    warningMessage: remainingBackupCodes <= 2
                        ? `⚠️ CRITICAL: Only ${remainingBackupCodes} backup code(s) left! Regenerate them in security settings.`
                        : remainingBackupCodes <= 3
                            ? `⚠️ Warning: Only ${remainingBackupCodes} backup codes left`
                            : null,
                    accessToken,
                    refreshToken,
                    csrfToken: user.sessions[user.sessions.length - 1].csrfToken,
                    user: sanitizeUser(user),
                    usedBackupCode: true
                });
            } else {
                return res.json({
                    success: true,
                    message: 'Login successful',
                    accessToken,
                    refreshToken,
                    csrfToken: user.sessions[user.sessions.length - 1].csrfToken,
                    user: sanitizeUser(user)
                });
            }

        } catch (error) {
            console.error('TOTP verification during login error:', {
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
                message: 'Failed to verify authentication code'
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
                    success: false, // ✅ ADD THIS
                    message: 'Verification code is required'
                });
            }

            // ✅ FIND USER BY VERIFICATION CODE
            const user = await Users.findOne({
                emailVerifyCode: code,
                emailVerifyCodeExpires: { $gt: Date.now() },
            });

            if (!user) {
                console.warn('Invalid or expired verification code', {
                    ip, country, deviceInfo
                });

                // Cleanup failed verification
                const expiredUser = await Users.findOne({ emailVerifyCode: code });
                if (expiredUser && !expiredUser.isActive) {
                    await Users.deleteOne({ _id: expiredUser._id });
                }

                return res.status(400).json({
                    success: false, // ✅ ADD THIS
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

            // ✅ CLEAR CODE FIELDS
            user.emailVerifyCode = undefined;
            user.emailVerifyCodeExpires = undefined;
            user.isActive = true;
            await user.save();

            console.info('Email verified and device confirmed', {
                userId: user._id,
                email: user.email,
                ip,
                country,
                deviceInfo
            });

            // ✅ FIXED RESPONSE STRUCTURE
            res.status(200).json({
                success: true, // ✅ ADD THIS
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
                const user = await Users.findOne({ emailVerifyCode: code });
                if (user && !user.isActive) {
                    await Users.deleteOne({ _id: user._id });
                }
            } catch (cleanupError) {
                console.error('Cleanup failed during verification error:', cleanupError.message);
            }

            // ✅ FIXED ERROR RESPONSE
            res.status(500).json({
                success: false, // ✅ ADD THIS
                message: 'Server error during email verification'
            });
        }
    }),
];


export const resendVerifyEmail = [
    setSecurityHeaders,
    validate([
        body('usernameOrEmail').notEmpty().withMessage('Username or email is required'),
    ]),
    asyncHandler(async (req, res) => {
        const { usernameOrEmail } = req.body;
        const { ip, country, deviceInfo } = getClientInfo(req);

        console.info('Resend verify email route accessed', {
            body: { usernameOrEmail },
            ip,
            country,
            deviceInfo,
            timestamp: new Date().toISOString(),
        });

        try {
            // Find user by username or email
            const user = await Users.findOne({
                $or: [
                    { email: { $regex: `^${usernameOrEmail}$`, $options: 'i' } },
                    { username: { $regex: `^${usernameOrEmail}$`, $options: 'i' } },
                ],
                isActive: false // Only resend for unverified users
            });

            if (!user) {
                console.warn('User not found or already verified', {
                    usernameOrEmail,
                    ip,
                    country,
                    deviceInfo
                });
                return res.status(400).json({
                    success: false,
                    message: 'User not found or already verified'
                });
            }

            // Check if user has expired (24-hour window)
            const userAge = Date.now() - user.createdAt.getTime();
            const maxAge = 24 * 60 * 60 * 1000; // 24 hours

            if (userAge > maxAge) {
                console.warn('Registration expired, deleting user', {
                    userId: user._id,
                    email: user.email,
                    createdAt: user.createdAt,
                    ip,
                    country,
                    deviceInfo
                });

                await Users.deleteOne({ _id: user._id });
                return res.status(400).json({
                    success: false,
                    message: 'Registration expired. Please sign up again.',
                    action: 'signup'
                });
            }

            // Generate new 6-digit verification code
            const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
            user.emailVerifyCode = verificationCode;
            user.emailVerifyCodeExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

            await user.save();

            // Send verification email with new code
            const emailSent = await sendEmailData('email_verification', user.email, {
                username: user.username,
                verificationCode: verificationCode,
                supportEmail: 'support@quantumrobots.com'
            });

            if (!emailSent) {
                console.error('Failed to resend verification email', {
                    email: user.email,
                    ip,
                    country,
                    deviceInfo
                });
                return res.status(500).json({
                    success: false,
                    message: 'Failed to send verification email'
                });
            }

            console.info('Verification email resent successfully', {
                userId: user._id,
                email: user.email,
                ip,
                country,
                deviceInfo
            });

            res.status(200).json({
                success: true,
                message: 'Verification code resent to your email.',
                requiresEmailVerification: true,
                email: user.email,
                pendingTOTPEnable: user.pendingTOTPEnable || false,
                requiresTOTPSetup: user.pendingTOTPEnable || false
            });

        } catch (error) {
            console.error('Resend verify email error', {
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
                message: 'Server error while resending verification email'
            });
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
                user.emailVerifyCode = verificationCode;
                user.emailVerifyCodeExpires = new Date(Date.now() + 15 * 60 * 1000);
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

            // ✅ FIXED TOTP LOGIC: Handle TOTP setup during login
            if (user.pendingTOTPEnable && !user.twoFactorSetupCompleted) {
                // User registered with TOTP but hasn't completed setup
                console.info('TOTP enabled during registration but not setup - prompting setup during login', {
                    userId: user._id,
                    ip,
                    country,
                    deviceInfo
                });

                return res.status(200).json({
                    success: false,
                    message: 'TOTP setup required. You enabled TOTP during registration. Please complete setup now.',
                    requiresTOTPSetup: true, // ✅ This tells frontend to go to TOTP setup
                    usernameOrEmail: usernameOrEmail,
                    fingerprint: fingerprint
                });
            }

            // ✅ Handle TOTP verification for users who have completed setup
            if (user.twoFactorEnabled && user.twoFactorSetupCompleted) {
                // User has TOTP fully set up - require TOTP code
                console.info('TOTP enabled and setup - requiring verification code', {
                    userId: user._id,
                    ip,
                    country,
                    deviceInfo
                });

                return res.status(200).json({
                    success: false,
                    message: 'TOTP code required for login',
                    requiresTOTPCode: true,
                    usernameOrEmail: usernameOrEmail,
                    fingerprint: fingerprint
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
                return res.status(404).json({
                    success: false, // ✅ ADD THIS
                    message: 'User not found'
                });
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
                return res.status(400).json({
                    success: false, // ✅ ADD THIS
                    message: 'Invalid or expired verification code'
                });
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

            // ✅ FIXED RESPONSE - ADD success: true
            return res.json({
                success: true, // ✅ ADD THIS LINE
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
            return res.status(500).json({
                success: false, // ✅ ADD THIS
                message: 'Server error during device verification'
            });
        }
    }),
];


export const resendVerifyDevice = [
    setSecurityHeaders,
    validate([
        body('usernameOrEmail').notEmpty().withMessage('Username or email is required'),
        body('fingerprint').custom((value) => DEV_MODE || value).withMessage('Device fingerprint is required'),
    ]),
    asyncHandler(async (req, res) => {
        const { usernameOrEmail, fingerprint } = req.body;
        const { ip, country, deviceInfo } = getClientInfo(req);

        console.info('Resend device verification route accessed', {
            body: { usernameOrEmail, fingerprint },
            ip,
            country,
            deviceInfo,
            timestamp: new Date().toISOString(),
        });

        try {
            // Find active user by username or email
            const user = await Users.findOne({
                $or: [
                    { email: { $regex: `^${usernameOrEmail}$`, $options: 'i' } },
                    { username: { $regex: `^${usernameOrEmail}$`, $options: 'i' } },
                ],
                isActive: true // Only active users can have device verification
            });

            if (!user) {
                console.warn('User not found for device verification resend', {
                    usernameOrEmail,
                    ip,
                    country,
                    deviceInfo
                });
                return res.status(404).json({
                    success: false,
                    message: 'User not found'
                });
            }

            // Check if device is already verified
            if (user.isDeviceVerified(fingerprint)) {
                console.warn('Device already verified', {
                    userId: user._id,
                    fingerprint,
                    ip,
                    country,
                    deviceInfo
                });
                return res.status(400).json({
                    success: false,
                    message: 'This device is already verified'
                });
            }

            // Find existing unverified device or create new one
            const existingDeviceIndex = user.devices.findIndex(device =>
                device.fingerprint === fingerprint &&
                device.status === 'NOT CONFIRMED'
            );

            // Generate new verification code
            const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
            const verificationCodeExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
            const expiresAt = new Date(Date.now() + 2 * 60 * 60 * 1000); // 2 hours

            if (existingDeviceIndex !== -1) {
                // Update existing device verification
                user.devices[existingDeviceIndex].verificationCode = verificationCode;
                user.devices[existingDeviceIndex].verificationCodeExpires = verificationCodeExpires;
                user.devices[existingDeviceIndex].expiresAt = expiresAt;
                user.devices[existingDeviceIndex].deviceInfo = deviceInfo;
                user.devices[existingDeviceIndex].ip = ip;
                user.devices[existingDeviceIndex].country = country;
                user.devices[existingDeviceIndex].createdAt = new Date();
            } else {
                // Add new device verification
                user.devices.push({
                    fingerprint,
                    status: 'NOT CONFIRMED',
                    deviceInfo,
                    ip,
                    country,
                    verificationCode,
                    verificationCodeExpires,
                    createdAt: new Date(),
                    expiresAt
                });
            }

            await user.save();

            // Send device verification email
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
                console.error('Failed to send device verification email', {
                    email: user.email,
                    ip,
                    country,
                    deviceInfo
                });
                return res.status(500).json({
                    success: false,
                    message: 'Failed to send verification email'
                });
            }

            console.info('Device verification code resent successfully', {
                userId: user._id,
                email: user.email,
                fingerprint,
                ip,
                country,
                deviceInfo
            });

            res.status(200).json({
                success: true,
                message: 'Device verification code resent successfully. Please check your email.',
                requiresDeviceVerification: true,
                fingerprint: fingerprint
            });

        } catch (error) {
            console.error('Resend device verification error', {
                error: error.message,
                stack: error.stack,
                usernameOrEmail,
                fingerprint,
                ip,
                country,
                deviceInfo,
                timestamp: new Date().toISOString(),
            });
            return res.status(500).json({
                success: false,
                message: 'Server error while resending device verification code'
            });
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
    asyncHandler(async (req, res) => {
        const { refreshToken } = req.body;
        const csrfToken = req.headers['x-csrf-token'];
        const { ip, country, deviceInfo } = getClientInfo(req);

        console.info('🚪 LOGOUT - Request received', {
            hasRefreshToken: !!refreshToken,
            refreshTokenLength: refreshToken?.length,
            hasCsrfToken: !!csrfToken,
            ip,
            country,
            timestamp: new Date().toISOString(),
        });

        // If no refresh token, just return success
        if (!refreshToken) {
            console.warn('⚠️ LOGOUT - No refresh token provided');
            return res.json({
                success: true,
                message: 'Logout completed (no token provided)'
            });
        }

        try {
            let userId;

            // ATTEMPT 1: Try to verify with RS256
            try {
                const payload = jwt.verify(refreshToken, publicKey, {
                    algorithms: ['RS256'],
                    issuer: ISSUER,
                    audience: AUDIENCE
                });
                userId = payload.userId;
                console.debug('🔐 LOGOUT - RS256 verification successful', { userId });
            } catch (verifyError) {
                // ATTEMPT 2: Decode without verification
                console.warn('⚠️ LOGOUT - RS256 failed, decoding:', verifyError.message);
                const decoded = jwt.decode(refreshToken);
                if (decoded && decoded.userId) {
                    userId = decoded.userId;
                    console.debug('🔍 LOGOUT - Decoded token', { userId });
                }
            }

            // If we got a userId, try to clear sessions
            if (userId) {
                const user = await Users.findById(userId);
                if (user) {
                    const sessionsBefore = user.sessions.length;

                    // Remove sessions matching this refresh token
                    user.sessions = user.sessions.filter(session =>
                        session.token !== refreshToken
                    );

                    const sessionsRemoved = sessionsBefore - user.sessions.length;
                    await user.save();

                    console.info('✅ LOGOUT - Sessions cleared', {
                        userId: user._id,
                        email: user.email,
                        sessionsRemoved,
                        remainingSessions: user.sessions.length
                    });
                }
            }

            // ALWAYS return success (even if verification failed)
            console.info('🎉 LOGOUT - Success response sent');
            return res.json({
                success: true,
                message: 'Logged out successfully'
            });

        } catch (error) {
            console.error('❌ LOGOUT - Unexpected error:', {
                error: error.message,
                stack: error.stack?.split('\n')[0] // First line only
            });

            // STILL return success - frontend should clear local state regardless
            return res.json({
                success: true,
                message: 'Logout completed (backend error handled)'
            });
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
                return res.status(404).json({
                    success: false, // ✅ ADD success property
                    message: 'User not found'
                });
            }
            if (!user.isActive) {
                console.warn('Email not verified for password reset', { email, ip, country, deviceInfo });
                return res.status(401).json({
                    success: false, // ✅ ADD success property
                    message: 'Email not verified'
                });
            }

            // ✅ GENERATE 6-DIGIT CODE
            const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
            user.passwordResetCode = resetCode;
            user.passwordResetCodeExpires = new Date(Date.now() + 15 * 60 * 1000);
            await user.save();

            // Send password reset email with CODE
            const emailSent = await sendEmailData('password_reset', email, {
                username: user.username,
                resetCode: resetCode, // 6-digit code
                supportEmail: 'support@quantumrobots.com'
            });

            if (!emailSent) {
                console.error('Failed to send password reset email via external service', { email, ip, country, deviceInfo });
                return res.status(500).json({
                    success: false, // ✅ ADD success property
                    message: 'Failed to send password reset email'
                });
            }

            console.info('Password reset code sent', { email, ip, country, deviceInfo });
            res.json({
                success: true,
                message: 'Password reset code sent. Please check your email.'
            });
        } catch (error) {
            console.error('Request password reset error', error);
            res.status(500).json({
                success: false, // ✅ ADD success property
                message: 'Server error during password reset request'
            });
        }
    }),
];

// ✅ verifyResetCode endpoint
// ✅ UPDATED verifyResetCode - email comes from either params or authenticated user
export const verifyResetCode = [
    setSecurityHeaders,
    asyncHandler(async (req, res) => {
        const { code } = req.body;
        const { ip, country, deviceInfo } = getClientInfo(req);

        console.info('Verify reset code route accessed', {
            body: { code: '[REDACTED]' },
            ip,
            country,
            deviceInfo,
            timestamp: new Date().toISOString(),
        });

        try {
            let user;
            let email;

            // ✅ HANDLE BOTH SCENARIOS:
            if (req.user && req.user.id) {
                // Scenario 1: User is authenticated (from app settings)
                user = await Users.findById(req.user.id);
                if (!user) {
                    return res.status(404).json({
                        success: false,
                        message: 'User not found'
                    });
                }
                email = user.email; // Use the authenticated user's email
            } else if (req.body.email) {
                // Scenario 2: User is not authenticated (from forgot password)
                email = req.body.email;
                user = await Users.findOne({ email });
                if (!user) {
                    return res.status(404).json({
                        success: false,
                        message: 'User not found'
                    });
                }
            } else {
                return res.status(400).json({
                    success: false,
                    message: 'Email is required'
                });
            }

            // ✅ VERIFY 6-DIGIT CODE
            const isValid = user.passwordResetCode === code &&
                user.passwordResetCodeExpires > new Date();

            if (!isValid) {
                console.warn('Invalid or expired reset code', { email, ip, country, deviceInfo });
                return res.status(400).json({
                    success: false,
                    message: 'Invalid or expired reset code'
                });
            }

            console.info('Reset code verified', { userId: user._id, email: user.email, ip, country, deviceInfo });
            res.status(200).json({
                success: true,
                message: 'Reset code verified successfully',
                email: user.email // ✅ Return email for frontend to use in next step
            });
        } catch (error) {
            console.error('Verify reset code error', error);
            return res.status(500).json({
                success: false,
                message: 'Server error during code verification'
            });
        }
    }),
];

// ✅ CORRECTED resetPassword - NO code required (already verified)
export const resetPassword = [
    setSecurityHeaders,
    validate([
        body('email').isEmail().withMessage('Email is required'),
        body('newPassword')
            .matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/)
            .withMessage('Password must be at least 8 characters, include a letter, number, and special character'),
        body('confirmPassword')
            .custom((value, { req }) => value === req.body.newPassword)
            .withMessage('Passwords do not match'),
    ]),
    asyncHandler(async (req, res) => {
        const { email, newPassword } = req.body; // ✅ NO code parameter
        const { ip, country, deviceInfo } = getClientInfo(req);

        console.info('Reset password route accessed', {
            body: { email, newPassword: '[REDACTED]' },
            ip,
            country,
            deviceInfo,
            timestamp: new Date().toISOString(),
        });

        try {
            const user = await Users.findOne({ email });
            if (!user) {
                return res.status(404).json({
                    success: false, // ✅ ADD success property
                    message: 'User not found'
                });
            }

            // ✅ CHECK IF USER HAS VALID RESET CODE (proves they passed verification)
            if (!user.passwordResetCode || user.passwordResetCodeExpires < new Date()) {
                return res.status(400).json({
                    success: false, // ✅ ADD success property
                    message: 'Please verify reset code first'
                });
            }

            const isSamePassword = await bcrypt.compare(newPassword, user.password);
            if (isSamePassword) {
                return res.status(400).json({
                    success: false, // ✅ ADD success property
                    message: 'New password cannot be the same as the old password'
                });
            }

            user.password = newPassword;
            // ✅ CLEAR RESET CODE AFTER SUCCESSFUL PASSWORD CHANGE
            user.passwordResetCode = undefined;
            user.passwordResetCodeExpires = undefined;
            await user.save();

            console.info('Password reset successfully', {
                userId: user._id,
                email: user.email,
                ip,
                country,
                deviceInfo
            });

            res.json({
                success: true,
                message: 'Password reset successful! You can now log in with your new password.'
            });
        } catch (error) {
            console.error('Reset password error', error);
            return res.status(500).json({
                success: false, // ✅ ADD success property
                message: 'Server error during password reset'
            });
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