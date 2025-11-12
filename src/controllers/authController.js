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

// export const register = [
//     setSecurityHeaders,
//     validate([
//         ...usernameValidation,
//         body('email').isEmail().withMessage('Invalid email format'),
//         ...passwordValidation,
//     ]),
//     asyncHandler(async (req, res) => {
//         const { username, email, password } = req.body;
//         const ip = requestIp.getClientIp(req);
//         const geo = geoip.lookup(ip);
//         const country = geo ? geo.country : 'unknown';
//         const deviceInfo = req.headers['user-agent'] || 'unknown';

//         console.info('Register route accessed', {
//             body: { username, email, password: '[REDACTED]' },
//             ip,
//             country,
//             deviceInfo,
//             timestamp: new Date().toISOString(),
//         });

//         try {
//             const exists = await Users.findOne({ $or: [{ email }, { username }] });
//             if (exists) {
//                 console.warn('User already exists', { email, username, ip, country, deviceInfo });
//                 return res.status(400).json({ message: 'User with this email or username already exists' });
//             }

//             const profileImage = `https://api.dicebear.com/9.x/avataaars/svg?seed=${username}`;
//             const user = new Users({
//                 username,
//                 email,
//                 password,
//                 profileImage,
//                 isActive: false,
//             });

//             const token = await user.generateEmailVerifyToken();
//             await user.save();
//             console.info('User registered', { email, userId: user._id, ip, country, deviceInfo });

//             const emailSent = await sendVerificationEmail(email, null, token);
//             if (!emailSent) {
//                 console.error('Failed to send verification email', { email, ip, country, deviceInfo });
//                 return res.status(500).json({ message: 'Failed to send verification email' });
//             }

//             res.status(201).json({ message: 'Verification email sent. Tap the token in the email to copy it and paste it in the app.' });
//         } catch (error) {
//             console.error('Registration error', {
//                 error: error.message,
//                 stack: error.stack,
//                 email,
//                 ip,
//                 country,
//                 deviceInfo,
//                 timestamp: new Date().toISOString(),
//             });
//             res.status(500).json({ message: 'Server error during registration' });
//         }
//     }),
// ];

export const register = [
    async (req, res) => {
        res.status(200).json({
            message: "✅ Register route is alive",
            method: req.method,
            timestamp: new Date().toISOString(),
            url: req.originalUrl,
            ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
        });
    },
];


export const verifyEmail = [
    setSecurityHeaders,
    validate([
        body('token').notEmpty().withMessage('Verification token is required'),
    ]),
    asyncHandler(async (req, res) => {
        const { token } = req.body;
        const ip = requestIp.getClientIp(req);
        const geo = geoip.lookup(ip);
        const country = geo ? geo.country : 'unknown';
        const deviceInfo = req.headers['user-agent'] || 'unknown';

        console.info('Verify email route accessed', {
            body: { token: '[REDACTED]' },
            ip,
            country,
            deviceInfo,
            timestamp: new Date().toISOString(),
        });

        try {
            const user = await Users.findOne({
                emailVerifyToken: token,
                emailVerifyExpires: { $gt: Date.now() },
            });

            if (!user) {
                console.warn('Invalid or expired verification token', { ip, country, deviceInfo });
                return res.status(400).json({ message: 'Invalid or expired verification token' });
            }

            user.emailVerifyToken = undefined;
            user.emailVerifyExpires = undefined;
            user.isActive = true;
            await user.save();

            console.info('Email verified', { userId: user._id, email: user.email, ip, country, deviceInfo });
            res.status(200).json({ message: 'Email verified successfully! You can now log in.' });
        } catch (error) {
            console.error('Email verification error', {
                error: error.message,
                stack: error.stack,
                ip,
                country,
                deviceInfo,
                timestamp: new Date().toISOString(),
            });
            res.status(500).json({ message: 'Server error during email verification' });
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
        const ip = requestIp.getClientIp(req);
        const geo = geoip.lookup(ip);
        const country = geo ? geo.country : 'unknown';
        const deviceInfo = req.headers['user-agent'] || 'unknown';

        console.info('Resend verify email route accessed', {
            body: { usernameOrEmail },
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
                console.warn('User not found for resend verification email', { usernameOrEmail, ip, country, deviceInfo });
                return res.status(404).json({ message: 'User not found' });
            }

            if (user.isActive) {
                console.warn('Email already verified', { usernameOrEmail, ip, country, deviceInfo });
                return res.status(400).json({ message: 'Email already verified' });
            }

            const token = await user.generateEmailVerifyToken();
            await user.save();

            const emailSent = await sendVerificationEmail(user.email, null, token);
            if (!emailSent) {
                console.error('Failed to send verification email', { email: user.email, ip, country, deviceInfo });
                return res.status(500).json({ message: 'Failed to send verification email' });
            }

            console.info('Verification email resent', { userId: user._id, email: user.email, ip, country, deviceInfo });
            res.status(200).json({ message: 'Verification email resent successfully' });
        } catch (error) {
            console.error('Resend verification email error', {
                error: error.message,
                stack: error.stack,
                usernameOrEmail,
                ip,
                country,
                deviceInfo,
                timestamp: new Date().toISOString(),
            });
            res.status(500).json({ message: 'Server error during resend verification email' });
        }
    }),
];

export const resendVerifyDevice = [
    setSecurityHeaders,
    validate([
        body('usernameOrEmail').notEmpty().withMessage('Username or email is required'),
        body('fingerprint').notEmpty().withMessage('Device fingerprint is required'),
    ]),
    asyncHandler(async (req, res) => {
        const { usernameOrEmail, fingerprint } = req.body;
        const ip = requestIp.getClientIp(req);
        const geo = geoip.lookup(ip);
        const country = geo ? geo.country : 'unknown';
        const deviceInfo = req.headers['user-agent'] || 'unknown';

        console.info('Resend verify device route accessed', {
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
            });

            if (!user) {
                console.warn('User not found for resend device verification', { usernameOrEmail, ip, country, deviceInfo });
                return res.status(404).json({ message: 'User not found' });
            }

            if (!user.isActive) {
                console.warn('Email not verified for resend device verification', { usernameOrEmail, ip, country, deviceInfo });
                return res.status(400).json({ message: 'Please verify your email first' });
            }

            user.deviceVerifyToken = undefined;
            user.deviceVerifyExpires = undefined;
            user.deviceVerifyFingerprint = undefined;

            const otp = await user.generateDeviceVerifyToken(fingerprint);
            await user.save();

            const emailSent = await sendDeviceVerificationEmail(user.email, otp, deviceInfo, ip);
            if (!emailSent) {
                console.error('Failed to send device verification email', { email: user.email, ip, country, deviceInfo });
                return res.status(500).json({ message: 'Failed to send device verification email' });
            }

            console.info('Device verification OTP resent', { userId: user._id, email: user.email, ip, country, deviceInfo });
            res.status(200).json({ message: 'Device verification OTP resent successfully' });
        } catch (error) {
            console.error('Resend device verification error', {
                error: error.message,
                stack: error.stack,
                usernameOrEmail,
                ip,
                country,
                deviceInfo,
                timestamp: new Date().toISOString(),
            });
            res.status(500).json({ message: 'Server error during resend device verification' });
        }
    }),
];

export const login = [
    setSecurityHeaders,
    validate([
        body('usernameOrEmail').notEmpty().withMessage('Username or email is required please'),
        body('password').optional().notEmpty().withMessage('Password is required please'),
        body('fingerprint').custom((value) => DEV_MODE || value).withMessage('Device fingerprint is required'),
        body('totp').optional().isLength({ min: 6, max: 6 }).withMessage('TOTP must be 6 digits'),
    ]),
    asyncHandler(async (req, res) => {
        const { usernameOrEmail, password, fingerprint, totp } = req.body;
        const ip = requestIp.getClientIp(req);
        const geo = geoip.lookup(ip);
        const country = geo ? geo.country : 'unknown';
        const deviceInfo = req.headers['user-agent'] || 'unknown';

        console.info('Login route accessed', {
            body: { usernameOrEmail, fingerprint, totp: totp ? '[REDACTED]' : undefined, password: password ? '[REDACTED]' : undefined },
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
                console.warn('Invalid login attempt', { usernameOrEmail, ip, country, deviceInfo });
                return res.status(400).json({ message: 'Invalid credentials' });
            }

            if (!user.isActive) {
                console.warn('Email not verified', { usernameOrEmail, ip, country, deviceInfo });
                const token = await user.generateEmailVerifyToken();
                await user.save();
                const emailSent = await sendVerificationEmail(user.email, null, token);
                if (!emailSent) {
                    console.error('Failed to send verification email during login', { email: user.email, ip, country, deviceInfo });
                    return res.status(500).json({ message: 'Failed to send verification email' });
                }
                return res.status(400).json({ message: 'Please verify your email to continue', requiresEmailVerification: true });
            }

            if (password && !(await user.verifyPassword(password))) {
                console.warn('Invalid password', { usernameOrEmail, ip, country, deviceInfo });
                return res.status(400).json({ message: 'Invalid credentials' });
            }

            if (user.twoFactorEnabled && !DEV_MODE) {
                if (!totp) {
                    console.warn('TOTP required', { userId: user._id, ip, country, deviceInfo });
                    return res.status(400).json({ message: 'TOTP required', requiresTotp: true });
                }
                const isValid = speakeasy.totp.verify({
                    secret: user.twoFactorSecret,
                    encoding: 'base32',
                    token: totp,
                });
                if (!isValid) {
                    console.warn('Invalid TOTP', { userId: user._id, ip, country, deviceInfo });
                    return res.status(400).json({ message: 'Invalid TOTP' });
                }
            }

            const existingFingerprints = user.sessions.map(s => s.fingerprint);
            const isNewDevice = fingerprint && !existingFingerprints.includes(fingerprint) && !DEV_MODE;

            if (isNewDevice) {
                try {
                    const otp = await user.generateDeviceVerifyToken(fingerprint);
                    const emailSent = await sendDeviceVerificationEmail(user.email, otp, deviceInfo, ip);
                    if (!emailSent) {
                        console.error('Failed to send device verification email', { email: user.email, ip, country, deviceInfo });
                        return res.status(500).json({ message: 'Failed to send verification email' });
                    }
                    await user.save();
                    console.info('New device detected; OTP sent', {
                        userId: user._id,
                        fingerprint,
                        ip,
                        country,
                        deviceInfo,
                        deviceVerifyFingerprint: user.deviceVerifyFingerprint,
                        deviceVerifyExpires: user.deviceVerifyExpires,
                    });
                    return res.status(200).json({ message: 'New device detected. Verify with OTP sent to your email.', requiresOtp: true });
                } catch (error) {
                    console.error('Error during device verification setup', {
                        error: error.message,
                        stack: error.stack,
                        userId: user._id,
                        ip,
                        country,
                        deviceInfo,
                    });
                    return res.status(500).json({ message: 'Failed to set up device verification' });
                }
            }

            user.lastLogin = new Date();
            user.lastLoginIp = ip;
            user.lastLoginDevice = deviceInfo;
            await user.cleanSessions();

            const accessToken = await user.generateAccessToken();
            const refreshToken = await user.generateRefreshToken(fingerprint || 'dev-mode', ip, country, deviceInfo);

            await user.save();
            console.info('Login successful', { userId: user._id, username: user.username, ip, country, deviceInfo });

            return res.json({
                accessToken,
                refreshToken,
                csrfToken: user.sessions[user.sessions.length - 1].csrfToken,
                user: sanitizeUser(user),
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
            return res.status(500).json({ message: 'Server error during login' });
        }
    }),
];

export const verifyDevice = [
    setSecurityHeaders,
    validate([
        body('otp').isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 characters'),
        body('fingerprint').notEmpty().withMessage('Device fingerprint is required'),
        body('usernameOrEmail').notEmpty().withMessage('Username or email is required'),
    ]),
    asyncHandler(async (req, res) => {
        const { otp, fingerprint, usernameOrEmail } = req.body;
        const ip = requestIp.getClientIp(req);
        const geo = geoip.lookup(ip);
        const country = geo ? geo.country : 'unknown';
        const deviceInfo = req.headers['user-agent'] || 'unknown';

        console.info('Verify device route accessed', {
            body: { usernameOrEmail, fingerprint, otp: '[REDACTED]' },
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
                deviceVerifyFingerprint: fingerprint,
                deviceVerifyExpires: { $gt: Date.now() },
            });

            if (!user) {
                console.warn('Invalid or expired device verification', {
                    usernameOrEmail,
                    fingerprint,
                    ip,
                    country,
                    deviceInfo,
                    timestamp: new Date().toISOString(),
                    usersFound: await Users.find({
                        $or: [
                            { email: { $regex: `^${usernameOrEmail}$`, $options: 'i' } },
                            { username: { $regex: `^${usernameOrEmail}$`, $options: 'i' } },
                        ],
                    }).countDocuments(),
                    fingerprintMatch: await Users.find({ deviceVerifyFingerprint: fingerprint }).countDocuments(),
                    expiresValid: await Users.find({ deviceVerifyExpires: { $gt: Date.now() } }).countDocuments(),
                });
                return res.status(400).json({ message: 'Invalid or expired verification' });
            }

            const isMatch = await bcrypt.compare(otp, user.deviceVerifyToken);
            if (!isMatch) {
                console.warn('Invalid OTP', { userId: user._id, ip, country, deviceInfo });
                return res.status(400).json({ message: 'Invalid OTP' });
            }

            user.deviceVerifyToken = undefined;
            user.deviceVerifyExpires = undefined;
            user.deviceVerifyFingerprint = undefined;

            user.lastLogin = new Date();
            user.lastLoginIp = ip;
            user.lastLoginDevice = deviceInfo;
            await user.cleanSessions();

            const accessToken = await user.generateAccessToken();
            const refreshToken = await user.generateRefreshToken(fingerprint, ip, country, deviceInfo);
            await user.save();

            console.info('Device verified successfully', { userId: user._id, username: user.username, ip, country, deviceInfo });
            res.json({
                accessToken,
                refreshToken,
                csrfToken: user.sessions[user.sessions.length - 1].csrfToken,
                user: sanitizeUser(user),
            });
        } catch (error) {
            console.error('Verify device error', {
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
        const ip = requestIp.getClientIp(req);
        const geo = geoip.lookup(ip);
        const country = geo ? geo.country : 'unknown';
        const deviceInfo = req.headers['user-agent'] || 'unknown';

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
                    sessionFound: user.sessions.some(s => s.token === refreshToken),
                    csrfMatch: user.sessions.some(s => s.csrfToken === csrfToken),
                });
                return res.status(401).json({ message: 'Invalid refresh token or CSRF token' });
            }
            const session = user.sessions[sessionIndex];

            if (!DEV_MODE && fingerprint && session.fingerprint !== fingerprint) {
                const trustedFingerprints = user.sessions.map(s => s.fingerprint);
                if (!trustedFingerprints.includes(fingerprint)) {
                    await sendSuspiciousActivityEmail(user.email, {
                        ip,
                        country,
                        deviceInfo,
                        message: 'New device detected during refresh. Re-login required.',
                    });
                    user.sessions = [];
                    await user.save();
                    console.warn('Fingerprint mismatch, sessions cleared', { userId: user._id, ip, country, deviceInfo });
                    return res.status(401).json({ message: 'New device detected. Please re-login to verify.' });
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
        const ip = requestIp.getClientIp(req);
        const geo = geoip.lookup(ip);
        const country = geo ? geo.country : 'unknown';
        const deviceInfo = req.headers['user-agent'] || 'unknown';

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
                    sessionFound: user.sessions.some(s => s.token === refreshToken),
                    csrfMatch: csrfToken ? user.sessions.some(s => s.csrfToken === csrfToken) : true,
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
        const ip = requestIp.getClientIp(req);
        const geo = geoip.lookup(ip);
        const country = geo ? geo.country : 'unknown';
        const deviceInfo = req.headers['user-agent'] || 'unknown';

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
            const emailSent = await sendPasswordResetEmail(email, resetUrl);

            if (!emailSent) {
                console.error('Failed to send password reset email', { email, ip, country, deviceInfo });
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
        const ip = requestIp.getClientIp(req);
        const geo = geoip.lookup(ip);
        const country = geo ? geo.country : 'unknown';
        const deviceInfo = req.headers['user-agent'] || 'unknown';

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
        const ip = requestIp.getClientIp(req);
        const geo = geoip.lookup(ip);
        const country = geo ? geo.country : 'unknown';
        const deviceInfo = req.headers['user-agent'] || 'unknown';

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
        const ip = requestIp.getClientIp(req);
        const geo = geoip.lookup(ip);
        const country = geo ? geo.country : 'unknown';
        const deviceInfo = req.headers['user-agent'] || 'unknown';

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
        const ip = requestIp.getClientIp(req);
        const geo = geoip.lookup(ip);
        const country = geo ? geo.country : 'unknown';
        const deviceInfo = req.headers['user-agent'] || 'unknown';

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
        const ip = requestIp.getClientIp(req);
        const geo = geoip.lookup(ip);
        const country = geo ? geo.country : 'unknown';
        const deviceInfo = req.headers['user-agent'] || 'unknown';

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
        const ip = requestIp.getClientIp(req);
        const geo = geoip.lookup(ip);
        const country = geo ? geo.country : 'unknown';
        const deviceInfo = req.headers['user-agent'] || 'unknown';

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