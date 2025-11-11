import cron from "cron";
import http from "http";
import https from "https";
import Users from "../models/userModel.js";
import { logger } from "../logger/logger.js";

const job = new cron.CronJob("*/14 * * * *", async function () {
  const keepAlive = () =>
    new Promise((resolve, reject) => {
      try {
        const url = process.env.NODE_JS_API_URL;
        const client = url.startsWith("https") ? https : http;

        client
          .get(url, (res) => {
            if (res.statusCode === 200) {
              logger.info("Keep-alive request sent successfully", {
                url,
                statusCode: res.statusCode,
                timestamp: new Date().toISOString(),
              });
              resolve(true);
            } else {
              logger.error("Keep-alive request failed", {
                url,
                statusCode: res.statusCode,
                timestamp: new Date().toISOString(),
              });
              reject(new Error(`Status: ${res.statusCode}`));
            }
          })
          .on("error", (e) => {
            logger.error("Error while sending keep-alive request", {
              url,
              error: e.message,
              timestamp: new Date().toISOString(),
            });
            reject(e);
          });
      } catch (err) {
        reject(err);
      }
    });

  // Retry keep-alive up to 3 times
  const maxRetries = 3;
  for (let i = 0; i < maxRetries; i++) {
    try {
      await keepAlive();
      break;
    } catch (error) {
      if (i < maxRetries - 1) {
        logger.info(`Retrying keep-alive request (${i + 2}/${maxRetries}) in 5 seconds...`);
        await new Promise((resolve) => setTimeout(resolve, 5000));
      } else {
        logger.error("Keep-alive request failed after max retries", {
          url: process.env.NODE_JS_API_URL,
          error: error.message,
        });
      }
    }
  }

  // Session cleanup
  try {
    const users = await Users.find({});
    let cleanedSessions = 0;
    for (const user of users) {
      const initialCount = user.sessions.length;
      await user.cleanSessions();
      cleanedSessions += initialCount - user.sessions.length;
    }
    logger.info("Session cleanup completed", {
      cleanedSessions,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    logger.error("Session cleanup failed fatal", {
      error: error.message,
      timestamp: new Date().toISOString(),
    });
  }
});

export default job;


// CRON JOB EXPLANATION:
// Cron jobs are scheduled tasks that run periodically at fixed intervals
// we want to send 1 GET request for every 14 minutes

// How to define a "Schedule"?
// You define a schedule using a cron expression, which consists of 5 fields representing:

//! MINUTE, HOUR, DAY OF THE MONTH, MONTH, DAY OF THE WEEK

//? EXAMPLES && EXPLANATION:
//* 14 * * * * - Every 14 minutes
//* 0 0 * * 0 - At midnight on every Sunday
//* 30 3 15 * * - At 3:30 AM, on the 15th of every month
//* 0 0 1 1 * - At midnight, on January 1st
//* 0 * * * * - Every hour