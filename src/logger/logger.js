// src/logger/logger.js
import pino from "pino";
import pinoHttp from "pino-http";
import crypto from "crypto";
import cron from "node-cron";
import axios from "axios";
import dotenv from "dotenv";

dotenv.config();

const isProduction = process.env.NODE_ENV === "production";
const fastApiUrl = process.env.FASTAPI_URL || "http://127.0.0.1:8000";
const recipientEmail = process.env.LOG_RECIPIENT_EMAIL || "festusdivinely@gmail.com";

// --- Logger setup ---
const logger = pino({
    level: process.env.LOG_LEVEL || (isProduction ? "info" : "debug"),
    transport: isProduction
        ? undefined // serverless: logs go to console
        : {
            target: "pino-pretty",
            options: {
                colorize: true,
                levelFirst: true,
                translateTime: "yyyy-mm-dd HH:MM:ss",
                ignore: "pid,hostname,time",
            },
        },
    timestamp: pino.stdTimeFunctions.isoTime,
    base: { pid: process.pid },
    redact: {
        paths: [
            "req.headers.authorization",
            "*.password",
            "*.emailVerifyToken",
            "*.token",
        ],
        censor: "[REDACTED]",
    },
});

// --- HTTP logger middleware ---
const httpLogger = pinoHttp({
    logger,
    genReqId: (req) => req.headers["x-request-id"] || crypto.randomUUID(),
    autoLogging: !isProduction,
});

// --- Optional: send logs (local dev only) ---
if (!isProduction) {
    const sendLogs = async (logContent, fileName) => {
        try {
            await axios.post(`${fastApiUrl}/send-log-email`, {
                logContent,
                fileName,
                recipientEmail,
            });
            logger.info(`✅ Sent log file ${fileName} to FastAPI`);
        } catch (err) {
            logger.error({ err: err.message, stack: err.stack }, "❌ Failed to send log file");
        }
    };

    // Example cron: run every day at midnight Lagos time
    cron.schedule(
        "0 0 * * *",
        async () => {
            logger.info("🕛 testing Cron tick (dev) — sending logs if any");
            // In dev, you could read logs from src/logs if you want
            // But on serverless, skip this
        },
        { timezone: "Africa/Lagos" }
    );
}

export { logger, httpLogger };

