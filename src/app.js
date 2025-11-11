import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import authRoute from "./routes/authRoute.js";
import botRoute from "./routes/botRoutes.js";
import errorHandler, { NotFoundError } from "./middleware/errorMiddleware.js";
import connectDb from "./config/mongodb.config.js";   // IMPORTANT FOR SERVERLESS

const app = express();

console.info("Initializing Express server");

// Ensure MongoDB is connected before every request (cached connection)
app.use(async (req, res, next) => {
    try {
        await connectDb();   // cached, fast, safe for Vercel
        next();
    } catch (err) {
        console.error("DB connection error in middleware", { error: err.message });
        next(err);
    }
});

// Helmet configuration (unchanged)
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
    console.info(" helmet configured without HSTS (development mode)");
} else {
    app.use(helmet(helmetConfig));
    console.info("Helmet security middleware configured (production mode)");
}

// Logging middleware - REMOVED httpLogger
// app.use(httpLogger);  ← DELETED

// Rate limiting for /api/auth
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: "Too many requests from this IP, please try again later.",
});
app.use("/api/auth", globalLimiter);
console.info("Rate limiting middleware configured");

// CORS configuration (unchanged)
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
console.info("CORS middleware configured", { origins: corsOrigins });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.use("/api/auth", authRoute);
app.use("/api/bots", botRoute);

// Root test endpoint
app.get("/", (req, res) => {
    res.send(`
    <html>
      <head><title>Quantum Robots API</title></head>
      <body style="font-family: Arial, sans-serif; text-align: center; padding: 2rem;">
        <h1>Quantum Robots API</h1>
        <p>Serverless function executed successfully.</p>
        <small>${new Date().toISOString()}</small>
      </body>
    </html>
  `);
});

// Not found handler
app.use((req, res, next) => {
    next(new NotFoundError(`Route ${req.originalUrl} not found`));
});

// Global error middleware
app.use(errorHandler);

export default app;   // IMPORTANT FOR VERCEL (NO LISTEN)