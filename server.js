// server.js
import "dotenv/config";
import { connectDb } from "./src/config/mongodb.config.js";
import app from "./src/app.js";
import http from "http";

// Log server startup
console.info("Starting server for Render deployment", {
    environment: process.env.NODE_ENV,
    node_version: process.version
});

// Handle uncaught exceptions and unhandled rejections
process.on("uncaughtException", (err) => {
    console.error("Uncaught Exception", {
        error: err.message,
        stack: err.stack,
        environment: process.env.NODE_ENV
    });
    // Don't exit immediately in production, let Render handle it
    if (process.env.NODE_ENV === 'production') {
        console.error("Uncaught exception in production - waiting for graceful shutdown");
    } else {
        process.exit(1);
    }
});

process.on("unhandledRejection", (reason, promise) => {
    console.error("Unhandled Rejection", {
        reason: reason instanceof Error ? reason.message : reason,
        environment: process.env.NODE_ENV
    });
    // In production, log but don't crash immediately
    if (process.env.NODE_ENV !== 'production') {
        process.exit(1);
    }
});

// Graceful shutdown handler for Render
process.on('SIGTERM', () => {
    console.info('SIGTERM received, starting graceful shutdown');
    server.close(() => {
        console.info('HTTP server closed');
        process.exit(0);
    });
});

// MongoDB connection with retry (optimized for Render)
const connectWithRetry = async (retries = 3, delay = 10000) => {
    for (let i = 0; i < retries; i++) {
        try {
            await connectDb();
            console.info("MongoDB connection established", {
                database: "mongodb",
                attempt: i + 1
            });
            return;
        } catch (error) {
            console.error("MongoDB connection attempt failed", {
                attempt: i + 1,
                error: error.message,
            });
            if (i < retries - 1) {
                console.info(`Retrying MongoDB connection in ${delay / 1000} seconds...`);
                await new Promise((resolve) => setTimeout(resolve, delay));
            } else {
                console.error("MongoDB connection failed after max retries", {
                    error: error.message,
                    environment: process.env.NODE_ENV
                });
                // In production, we might want to continue without DB for health checks
                if (process.env.NODE_ENV === 'production') {
                    console.warn("Continuing without MongoDB connection in production");
                } else {
                    process.exit(1);
                }
            }
        }
    }
};

// Initialize server
const initializeServer = async () => {
    try {
        // Connect to database first
        await connectWithRetry();

        // Port config for Render
        const PORT = process.env.PORT || 3000;

        // Start HTTP server
        const server = http
            .createServer(app)
            .listen(PORT, '0.0.0.0', () => {
                console.info(`🚀 Server running on port ${PORT}`, {
                    timestamp: new Date().toISOString(),
                    environment: process.env.NODE_ENV,
                    url: `http://0.0.0.0:${PORT}`
                });
            })
            .on('error', (error) => {
                console.error("Failed to start Express server", {
                    port: PORT,
                    error: error.message,
                    environment: process.env.NODE_ENV
                });
                process.exit(1);
            });

        return server;

    } catch (error) {
        console.error("Failed to initialize server", {
            error: error.message,
            environment: process.env.NODE_ENV
        });
        process.exit(1);
    }
};

// Start the server
const server = initializeServer();

export default server;