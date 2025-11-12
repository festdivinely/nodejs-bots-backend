import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import authRoutes from "./routes/authRoutes.js";
import botRoutes from "./routes/botRoutes.js";
import errorHandler, { NotFoundError } from "./middleware/errorMiddleware.js";
// REMOVED: connectDb import — NO LONGER NEEDED HERE

const app = express();

console.info("Initializing Express server");


app.get("/favicon.ico", (req, res) => res.status(204));

// DELETED: connectDb middleware — MOVED TO api/index.js

// Helmet configuration
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
    console.info("Helmet configured without HSTS (development mode)");
} else {
    app.use(helmet(helmetConfig));
    console.info("Helmet security middleware configured (production mode)");
}

// Rate limiting
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: "Too many requests from this IP, please try again later.",
});
app.use("/api/auth", globalLimiter);
console.info("Rate limiting middleware configured");

// CORS
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

// API root
app.get("/api/", (req, res) => {
    res.json({
        message: "Trade Divinely Bot API is LIVE",
        routes: ["/api/auth", "/api/bots"],
        time: new Date().toISOString()
    });
});


console.log("Loaded routes:", {
    hasAuthRoute: !!authRoutes,
    typeOfAuthRoute: typeof authRoutes,
    authRouteKeys: authRoutes?.stack?.map(r => r.route?.path || "[middleware]") || "no stack",
});

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/bots", botRoutes);

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

// Add this to your app.js temporarily
app.get('/api/debug', (req, res) => {
    console.log('Debug endpoint hit!');
    res.json({
        message: 'Debug endpoint working',
        timestamp: new Date().toISOString(),
        url: req.url,
        originalUrl: req.originalUrl,
        method: req.method
    });
});

// 404
app.use((req, res, next) => {
    next(new NotFoundError(`Route ${req.originalUrl} not found`));
});

// Error handler
app.use(errorHandler);

export default app;