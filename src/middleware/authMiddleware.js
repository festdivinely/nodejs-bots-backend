// backend/middleware/authMiddleware.js
import asyncHandler from "express-async-handler";
import jwt from "jsonwebtoken";
import Users from "../models/userModel.js";

const publicKey = process.env.PUBLIC_KEY;
if (!publicKey) {
    throw new Error("Missing PUBLIC_KEY environment variable");
}

const ISSUER = process.env.ISSUER || "quantumrobots.com";
const AUDIENCE = process.env.AUDIENCE || "api.quantumrobots.com";

// New: CSRF middleware for protected routes
export const csrfProtect = asyncHandler(async (req, res, next) => {
    const csrfToken = req.headers["x-csrf-token"];
    if (!csrfToken) {
        console.warn("Missing CSRF token", { route: req.originalUrl });
        return res.status(403).json({ message: "Missing CSRF token" });
    }

    const token = req.headers.authorization?.split(" ")[1];
    const payload = jwt.verify(token, publicKey, { algorithms: ["RS256"], issuer: ISSUER, audience: AUDIENCE });
    const user = await Users.findById(payload.userId);
    if (!user) {
        console.warn("User not found for CSRF check", { userId: payload.userId });
        return res.status(401).json({ message: "User not found" });
    }

    const session = user.sessions.find(s => s.expires > new Date() && !s.used);
    if (!session || session.csrfToken !== csrfToken) {
        console.warn("Invalid CSRF token", { userId: user._id, route: req.originalUrl });
        return res.status(403).json({ message: "Invalid CSRF token" });
    }
    next();
});

export const protect = asyncHandler(async (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
        console.warn("No token provided", { route: req.originalUrl });
        return res.status(401).json({ message: "Not authorized, no token provided" });
    }

    try {
        const decoded = jwt.verify(token, publicKey, {
            algorithms: ["RS256"],
            issuer: ISSUER,
            audience: AUDIENCE,
        });

        const user = await Users.findById(decoded.userId).select("-password -sessions -emailVerifyToken");
        if (!user) {
            console.warn("User not found for token", { userId: decoded.userId });
            return res.status(401).json({ message: "User not found" });
        }
        if (!user.isActive) {
            console.warn("Inactive user attempted access", { userId: decoded.userId });
            return res.status(403).json({ message: "User account is inactive" });
        }

        await user.cleanSessions();
        req.user = user;
        console.info("User authenticated", { userId: user.id, route: req.originalUrl });
        next();
    } catch (error) {
        console.error("Token verification failed", { error: error.message });
        if (error.name === "TokenExpiredError") {
            return res.status(401).json({ message: "Token expired, please refresh or login again" });
        }
        return res.status(401).json({ message: "Not authorized, token verification failed" });
    }
});

export const requireRole = (roles) => {
    return asyncHandler(async (req, res, next) => {
        if (!req.user || !roles.includes(req.user.role)) {
            console.warn("Insufficient permissions", { userId: req.user?.id, role: req.user?.role, requiredRoles: roles });
            return res.status(403).json({ message: `Forbidden: requires one of ${roles.join(", ")} role` });
        }
        console.info("Role check passed", { userId: req.user.id, role: req.user.role, route: req.originalUrl });
        next();
    });
};
// HTTPS enforcement (in app.js)