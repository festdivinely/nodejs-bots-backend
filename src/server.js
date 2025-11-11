import "dotenv/config";
import connectDb from "./config/mongodb.config.js";
import app from "./app.js";
import job from "./config/cron.js";
import http from "http";

// Log server startup
console.info("Starting server");

// Handle uncaught exceptions and unhandled rejections
process.on("uncaughtException", (err) => {
    console.error("Uncaught Exception", { error: err.message, stack: err.stack });
    process.exit(1);
});

process.on("unhandledRejection", (reason, promise) => {
    console.error("Unhandled Rejection", {
        reason: reason instanceof Error ? reason.message : reason,
        promise,
    });
    if (process.env.NODE_ENV !== "production") {
        process.exit(1);
    }
});

// MongoDB connection with retry
const connectWithRetry = async (retries = 5, delay = 5000) => {
    for (let i = 0; i < retries; i++) {
        try {
            await connectDb();
            console.info("MongoDB connection established", { database: "mongodb" });
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
                });
                process.exit(1);
            }
        }
    }
};

connectWithRetry();

// Start cron job with retry
const startCronWithRetry = async (retries = 3, delay = 5000) => {
    for (let i = 0; i < retries; i++) {
        try {
            job.start();
            console.info("Cron job started", { cron: "job" });
            return;
        } catch (error) {
            console.error("Failed to start cron job", {
                attempt: i + 1,
                error: error.message,
            });
            if (i < retries - 1) {
                console.info(`Retrying cron job start in ${delay / 1000} seconds...`);
                await new Promise((resolve) => setTimeout(resolve, delay));
            } else {
                console.error("Cron job failed to start after max retries", {
                    error: error.message,
                });
            }
        }
    }
};

startCronWithRetry();

// Port config
const PORT = process.env.PORT || process.env.DEFAULT_PORT || 3000;

// Start HTTP server
http
    .createServer(app)
    .listen(PORT, () => {
        console.info(
            `Express server started on port ${PORT} at ${new Date().toISOString()}`
        );
    })
    .on("error", (error) => {
        console.error("Failed to start Express server", {
            port: PORT,
            error: error.message,
        });
        process.exit(1);
    });