import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import authRoute from "./routes/authRoute.js";
import botRoute from "./routes/botRoutes.js";
import { logger, httpLogger } from "./logger/logger.js";
import errorHandler, { NotFoundError } from "./middleware/errorMiddleware.js";

const app = express();

logger.info("Initializing Express server");

// Helmet configuration (different for dev vs prod)
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
    logger.info("Helmet configured without HSTS (development mode)");
} else {
    app.use(helmet(helmetConfig));
    logger.info("Helmet security middleware configured (production mode)");
}

// HTTP request logging
app.use(httpLogger);

// Rate limiting (apply only to /api/auth)
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: "Too many requests from this IP, please try again later.",
});
app.use("/api/auth", globalLimiter);
logger.info("Rate limiting middleware configured");

// CORS configuration
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
logger.info("CORS middleware configured", { origins: corsOrigins });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.use("/api/auth", authRoute);
app.use("/api/bots", botRoute);

// Root route
app.get("/", (req, res) => {
    res.send(`
    <html>
      <head><title>Quantum Robots API</title></head>
      <body style="font-family: Arial, sans-serif; text-align: center; padding: 2rem;">
        <h1>🚀 Quantum Robots API</h1>
        <p>Server is running on port ${process.env.PORT || 3000}</p>
        <small>${new Date().toISOString()}</small>
      </body>
    </html>
  `);
});

// Not found handler
app.use((req, res, next) => {
    next(new NotFoundError(`Route ${req.originalUrl} not found`));
});

// Global error handler
app.use(errorHandler);

export default app;
