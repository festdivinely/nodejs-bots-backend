// src/logger.js
import fs from "fs";
import path from "path";
import pino from "pino";
import pinoHttp from "pino-http";
import axios from "axios";
import cron from "node-cron";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

// --- Ensure logs directory exists ---
const logDir = path.join(process.cwd(), "src", "logs");
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
}

// --- Config ---
const isProduction = process.env.NODE_ENV === "production";
const fastApiUrl = process.env.FASTAPI_URL || "http://127.0.0.1:8000";
const recipientEmail =
    process.env.LOG_RECIPIENT_EMAIL || "festusdivinely@gmail.com";

// --- Logger Setup ---
const transport = pino.transport({
    targets: isProduction
        ? [
            {
                target: "pino/file",
                options: {
                    destination: path.join(logDir, "app.log"),
                    mkdir: true,
                },
                level: "info",
            },
            {
                target: "pino/file",
                options: {
                    destination: path.join(logDir, "error.log"),
                    mkdir: true,
                },
                level: "error",
            },
        ]
        : [
            {
                target: "pino-pretty", // console in dev
                options: {
                    colorize: true,
                    levelFirst: true,
                    translateTime: "yyyy-mm-dd HH:MM:ss",
                    ignore: "pid,hostname,time",
                },
            },
            {
                target: "pino/file", // dev file logs
                options: {
                    destination: path.join(logDir, "app.log"),
                    mkdir: true,
                },
                level: "debug",
            },
            {
                target: "pino/file", // dev error logs
                options: {
                    destination: path.join(logDir, "error.log"),
                    mkdir: true,
                },
                level: "error",
            },
        ],
});

const logger = pino(
    {
        level: process.env.LOG_LEVEL || (isProduction ? "info" : "debug"),
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
    },
    transport
);

// --- Utility: Send and Delete Logs ---
const sendAndDeleteLogs = async (filePath) => {
    try {
        if (!fs.existsSync(filePath)) return;

        const stats = fs.statSync(filePath);
        if (stats.size === 0) return;

        const logContent = fs.readFileSync(filePath, "utf8");

        await axios.post(`${fastApiUrl}/send-log-email`, {
            logContent,
            fileName: path.basename(filePath),
            recipientEmail,
        });

        logger.info(`✅ Sent log file ${filePath} to FastAPI`);
        fs.unlinkSync(filePath);
        logger.info(`🗑️ Deleted log file ${filePath}`);
    } catch (error) {
        logger.error(
            { err: error.message, stack: error.stack },
            `❌ Failed to send log file ${filePath}`
        );
    }
};

// --- Cron: send logs daily at midnight Lagos time ---
if (isProduction) {
    cron.schedule(
        "0 0 * * *",
        async () => {
            const files = [
                path.join(logDir, "app.log"),
                path.join(logDir, "error.log"),
            ];

            let sentSomething = false;
            for (const filePath of files) {
                if (fs.existsSync(filePath) && fs.statSync(filePath).size > 0) {
                    await sendAndDeleteLogs(filePath);
                    sentSomething = true;
                }
            }

            if (!sentSomething) {
                logger.info("ℹ️ No logs to send today, skipping");
            }
        },
        { timezone: "Africa/Lagos" }
    );
}

// --- HTTP Logger ---
const httpLogger = pinoHttp({
    logger,
    genReqId: (req) => req.headers["x-request-id"] || crypto.randomUUID(),
    autoLogging: !isProduction,
});

// --- Simulation mode (dev only) ---
const simulateLogs = async () => {
    logger.info("👤 User JohnDoe logged in");
    logger.info("📄 User JohnDoe viewed dashboard");
    logger.warn("⚠️ Low balance warning for user JaneDoe");
    logger.error("💳 Payment gateway failed for transaction #12345");

    setTimeout(async () => {
        const files = [
            path.join(logDir, "app.log"),
            path.join(logDir, "error.log"),
        ];
        for (const file of files) {
            if (fs.existsSync(file) && fs.statSync(file).size > 0) {
                await sendAndDeleteLogs(file);
            }
        }
    }, 3000);
};

if (process.argv.includes("--simulate")) {
    simulateLogs();
}

export { logger, httpLogger, sendAndDeleteLogs };
