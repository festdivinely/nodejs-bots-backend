// app.js
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import errorHandler, { NotFoundError } from "./middleware/errorMiddleware.js";
import { dbHealthCheck, connectDb } from './config/mongodb.config.js'; // Import connectDb too

dotenv.config();

const app = express();
app.set("trust proxy", 1);
console.info("Initializing Express server");

// Initialize database connection first
console.info("Connecting to MongoDB Atlas...");
await connectDb().catch(error => {
    console.error('❌ Failed to connect to database:', error);
    process.exit(1);
});

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
    max: process.env.NODE_ENV === 'production' ? 50 : 100,
    message: {
        error: "Too many requests from this IP, please try again later.",
        retryAfter: "15 minutes"
    },
    standardHeaders: true,
    legacyHeaders: false,
});

app.use("/api/", globalLimiter);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: {
        error: "Too many authentication attempts, please try again later.",
        retryAfter: "15 minutes"
    }
});
app.use("/api/auth", authLimiter);

// ==================
// CORS
// ==================
const corsOrigins = process.env.CORS_ORIGINS
    ? process.env.CORS_ORIGINS.split(",")
    : ["https://your-frontend-domain.onrender.com", "http://localhost:3000"];

app.use(
    cors({
        origin: function (origin, callback) {
            if (!origin) return callback(null, true);
            if (corsOrigins.indexOf(origin) !== -1) {
                callback(null, true);
            } else {
                console.warn(`CORS blocked for origin: ${origin}`);
                callback(new Error('Not allowed by CORS'));
            }
        },
        methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
        allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token"],
        credentials: true,
        maxAge: 86400
    })
);

// ==================
// Body Parsing
// ==================
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// ==================
// Health Check Route
// ==================
app.get('/health', async (req, res) => {
    try {
        const dbStatus = await dbHealthCheck();

        res.status(200).json({
            status: dbStatus.status === 'healthy' ? 'OK' : 'Degraded',
            timestamp: new Date().toISOString(),
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            environment: process.env.NODE_ENV,
            database: dbStatus
        });
    } catch (error) {
        res.status(503).json({
            status: 'ERROR',
            timestamp: new Date().toISOString(),
            error: 'Health check failed',
            database: { status: 'unreachable' }
        });
    }
});

// Root route
app.get("/", (req, res) => {
    res.send(`
        <html>
        <head>
            <title>Trade Divinely Bot API</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body { 
                    font-family: 'Courier New', monospace; 
                    text-align: center; 
                    padding: 2rem; 
                    background:#000; 
                    color:#00ff41;
                    margin: 0;
                    min-height: 100vh;
                    display: flex;
                    flex-direction: column;
                    justify-content: center;
                    align-items: center;
                }
                .container {
                    max-width: 600px;
                    border: 1px solid #00ff41;
                    padding: 2rem;
                    border-radius: 10px;
                    background: rgba(0, 255, 65, 0.05);
                }
                h1 { 
                    margin-bottom: 1rem; 
                    text-shadow: 0 0 10px #00ff41;
                }
                .status {
                    color: #00ff41;
                    font-weight: bold;
                    margin: 1rem 0;
                }
                .endpoints {
                    text-align: left;
                    margin: 2rem 0;
                    background: rgba(0, 0, 0, 0.5);
                    padding: 1rem;
                    border-radius: 5px;
                }
                code {
                    background: #111;
                    padding: 0.2rem 0.5rem;
                    border-radius: 3px;
                    display: block;
                    margin: 0.5rem 0;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>TRADE DIVINELY BOT API</h1>
                <div class="status">🚀 Serverless backend is <strong>ALIVE</strong></div>
                <p><strong>${new Date().toISOString()}</strong></p>
                <div class="endpoints">
                    <strong>Available Endpoints:</strong>
                    <code>POST /api/auth/register</code>
                    <code>POST /api/auth/login</code>
                    <code>GET /api/bot/</code>
                    <code>GET /health</code>
                </div>
                <hr style="border-color: #00ff41; margin: 1rem 0;">
                <p>Environment: <strong>${process.env.NODE_ENV || 'development'}</strong></p>
            </div>
        </body>
        </html>
    `);
});

// ==================
// Routes
// ==================
console.info("Initializing routes", {
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV
});

// Use route files
import authRoutes from "./routes/authRoutes.js";
import botRoutes from "./routes/botRoutes.js";

app.use("/api/auth", authRoutes);
app.use("/api/bot", botRoutes);

// 404 Handler
app.use((req, res, next) => {
    next(new NotFoundError(`Route ${req.originalUrl} not found`));
});

// Error handler
app.use(errorHandler);

export default app;