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

// ----------------------------
// ✅ LOGGER SETUP
// ----------------------------
const logger = pino({
    level: process.env.LOG_LEVEL || (isProduction ? "info" : "debug"),
    transport: isProduction
        ? undefined // ✅ Production (Vercel) -> console only
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

// ----------------------------
// ✅ HTTP LOGGER MIDDLEWARE
// ----------------------------
const httpLogger = pinoHttp({
    logger,
    genReqId: (req) => req.headers["x-request-id"] || crypto.randomUUID(),
    autoLogging: !isProduction,
});

// ----------------------------
// ✅ DEV-ONLY: SEND LOGS / CRON
// (Disabled in production to avoid blocking Vercel)
// ----------------------------
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
            logger.error(
                { err: err.message, stack: err.stack },
                "❌ Failed to send log file"
            );
        }
    };

    // ✅ Dev-only cron (never runs on Vercel)
    cron.schedule(
        "0 0 * * *",
        async () => {
            logger.info("🕛 Cron tick (local dev only)");
        },
        { timezone: "Africa/Lagos" }
    );
}

// ✅ Export logger + middleware
export { logger, httpLogger };


