// app.js
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import connectDb from "./config/mongodb.config.js";
import errorHandler, { NotFoundError } from "./middleware/errorMiddleware.js";
import { protect, requireRole, csrfProtect } from "./middleware/authMiddleware.js";

import {
    registerLimiter,
    loginLimiter,
    verifyDeviceLimiter,
    verifyLimiter,
    refreshLimiter,
    logRequest,
    resendVerifyDeviceLimiter,
    resendVerifyEmailLimiter,
    resetLimiter
} from "./helpers/helperFunctions.js";

import {
    login,
    register,
    logout,
    requestPasswordReset,
    resetPassword,
    verifyEmail,
    resendVerifyEmail,
    resendVerifyDevice,
    refreshToken,
    updateProfileImage,
    updateUsername,
    getProfile,
    getAdminDashboard,
    verifyDevice,
    verifyResetToken,
} from "./controllers/authController.js";

import {
    getAllBots,
    getUserBots,
    acquireBot,
    updateUserBot,
    startUserBot,
    stopUserBot,
    deleteUserBot,
    updateBotProgress,
    createBotTemplate,
    updateBotTemplate,
} from "./controllers/botControllers.js";

dotenv.config();

const app = express();
app.set("trust proxy", 1);
console.info("Initializing Express server");

// ==================
// Connect to MongoDB (once per serverless instance)
// ==================
(async () => {
    try {
        await connectDb();
        console.log("✅ Database ready");
    } catch (err) {
        console.error("❌ Failed to connect to DB:", err);
        process.exit(1);
    }
})();

// ==================
// Security Middleware
// ==================
const helmetConfig = {
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            connectSrc: ["'self'", ...(process.env.CORS_ORIGINS?.split(",") || [])],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
        },
    },
};

if (process.env.NODE_ENV === "development") {
    app.use(helmet({ ...helmetConfig, hsts: false }));
} else {
    app.use(helmet(helmetConfig));
}

// ==================
// Rate Limiting
// ==================
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: "Too many requests from this IP, please try again later.",
});
app.use("/api/auth", globalLimiter);

// ==================
// CORS
// ==================
const corsOrigins = process.env.CORS_ORIGINS
    ? process.env.CORS_ORIGINS.split(",")
    : ["https://quantumrobots.com", "http://127.0.0.1:3000"];

app.use(
    cors({
        origin: corsOrigins,
        methods: ["GET", "POST", "PUT", "DELETE"],
        allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token"],
        credentials: true,
    })
);

// ==================
// Body Parsing
// ==================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Root
app.get("/", (req, res) => {
    res.send(`
        <html>
        <head><title>Trade Divinely Bot API</title></head>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 2rem; background:#000; color:#00ff41;">
        <h1>TRADE DIVINELY BOT API</h1>
        <p>Serverless backend is <strong>ALIVE</strong>.</p>
        <p><strong>${new Date().toISOString()}</strong></p>
        <hr>
        <p>API: <code>/api/auth/register</code></p>
      </body>
      </html>
      `);
});

// ==================
// Routes
// ==================
console.info("Initializing auth routes", {
    route: "/api/auth",
    timestamp: new Date().toISOString(),
});

// routes/allRoutes.js
const authRouter = express.Router();
const botRouter = express.Router();

// =====================
// AUTH ROUTES
// =====================
authRouter.post("/register", logRequest, registerLimiter, register);
authRouter.post("/login", logRequest, loginLimiter, login);
authRouter.post("/verify-device", logRequest, verifyDeviceLimiter, verifyDevice);
authRouter.post("/resend-verify-device", logRequest, resendVerifyDeviceLimiter, resendVerifyDevice);
authRouter.post("/logout", logRequest, protect, csrfProtect, logout);
authRouter.post("/request-password-reset", logRequest, resetLimiter, requestPasswordReset);
authRouter.post("/reset-password/:token", logRequest, resetLimiter, resetPassword);
authRouter.post("/verify-email", logRequest, verifyLimiter, verifyEmail);
authRouter.post("/resend-verify-email", logRequest, resendVerifyEmailLimiter, resendVerifyEmail);
authRouter.post("/refresh-token", logRequest, refreshLimiter, refreshToken);
authRouter.get("/profile", logRequest, protect, getProfile);
authRouter.get("/admin", logRequest, protect, requireRole(["admin"]), getAdminDashboard);
authRouter.put("/profile/image", logRequest, protect, csrfProtect, updateProfileImage);
authRouter.put("/profile/username", logRequest, protect, csrfProtect, updateUsername);
authRouter.get("/verify-reset-token/:token", logRequest, resetLimiter, verifyResetToken);

// =====================
// BOT ROUTES
// =====================
botRouter.post("/", protect, requireRole(["admin"]), createBotTemplate);
botRouter.patch("/:id", protect, requireRole(["admin"]), updateBotTemplate);
botRouter.get("/", getAllBots);
botRouter.get("/user", protect, getUserBots);
botRouter.post("/acquire", protect, acquireBot);
botRouter.patch("/:botId", protect, updateUserBot);
botRouter.post("/:botId/start", protect, startUserBot);
botRouter.post("/:botId/stop", protect, stopUserBot);
botRouter.delete("/:botId", protect, deleteUserBot);
botRouter.post("/:botId/progress", updateBotProgress);


app.use("/api/auth", authRouter);
app.use("/api/bots", botRouter);


// 404
app.use((req, res, next) => {
    next(new NotFoundError(`Route ${req.originalUrl} not found`));
});

// Error handler
app.use(errorHandler);

export default app;
