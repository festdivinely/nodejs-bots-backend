// === RATE LIMITERS ===
export const registerLimiter = rateLimit({
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

export const loginLimiter = rateLimit({
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

export const verifyDeviceLimiter = rateLimit({
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

export const resendVerifyDeviceLimiter = rateLimit({
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

export const resetLimiter = rateLimit({
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

export const refreshLimiter = rateLimit({
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

export const verifyLimiter = rateLimit({
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

export const resendVerifyEmailLimiter = rateLimit({
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
export const logRequest = (req, res, next) => {
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