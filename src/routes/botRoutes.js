import express from "express";
import { protect, requireRole } from "../middleware/authMiddleware.js";
import {
    getAllBots,
    getUserBots,
    acquireBot,
    updateUserBot,
    startUserBot,
    stopUserBot,
    deleteUserBot,
    updateBotProgress,
    createBotTemplate,
    updateBotTemplate,
} from "../controllers/botControllers.js";

const router = express.Router();

// Log route initialization
console.info("Initializing bot routes", { route: "/api/bots", timestamp: new Date().toISOString() });

// Create bot template (admin only)
router.post("/", protect, requireRole(["admin"]), (req, res, next) => {
    console.info("Create bot template route accessed", {
        method: req.method,
        path: req.originalUrl,
        userId: req.user?.id,
        timestamp: new Date().toISOString()
    });
    createBotTemplate(req, res, next);
});

// Update bot template (admin only)
router.patch("/:id", protect, requireRole(["admin"]), (req, res, next) => {
    console.info("Update bot template route accessed", {
        method: req.method,
        path: req.originalUrl,
        userId: req.user?.id,
        templateId: req.params.id,
        timestamp: new Date().toISOString()
    });
    updateBotTemplate(req, res, next);
});

// Get all bots (public route)
router.get("/", (req, res, next) => {
    console.info("Get all bots route accessed", {
        method: req.method,
        path: req.originalUrl,
        timestamp: new Date().toISOString()
    });
    getAllBots(req, res, next);
});

// Get user bots (requires auth)
router.get("/user", protect, (req, res, next) => {
    console.info("Get user bots route accessed", {
        method: req.method,
        path: req.originalUrl,
        userId: req.user?.id,
        timestamp: new Date().toISOString()
    });
    getUserBots(req, res, next);
});

// Acquire bot (requires auth)
router.post("/acquire", protect, (req, res, next) => {
    console.info("Acquire bot route accessed", {
        method: req.method,
        path: req.originalUrl,
        userId: req.user?.id,
        timestamp: new Date().toISOString()
    });
    acquireBot(req, res, next);
});

// Update user bot (requires auth)
router.patch("/:botId", protect, (req, res, next) => {
    console.info("Update user bot route accessed", {
        method: req.method,
        path: req.originalUrl,
        userId: req.user?.id,
        botId: req.params.botId,
        timestamp: new Date().toISOString()
    });
    updateUserBot(req, res, next);
});

// Start user bot (requires auth)
router.post("/:botId/start", protect, (req, res, next) => {
    console.info("Start user bot route accessed", {
        method: req.method,
        path: req.originalUrl,
        userId: req.user?.id,
        botId: req.params.botId,
        timestamp: new Date().toISOString()
    });
    startUserBot(req, res, next);
});

// Stop user bot (requires auth)
router.post("/:botId/stop", protect, (req, res, next) => {
    console.info("Stop user bot route accessed", {
        method: req.method,
        path: req.originalUrl,
        userId: req.user?.id,
        botId: req.params.botId,
        timestamp: new Date().toISOString()
    });
    stopUserBot(req, res, next);
});

// Delete user bot (requires auth)
router.delete("/:botId", protect, (req, res, next) => {
    console.info("Delete user bot route accessed", {
        method: req.method,
        path: req.originalUrl,
        userId: req.user?.id,
        botId: req.params.botId,
        timestamp: new Date().toISOString()
    });
    deleteUserBot(req, res, next);
});

// Update bot progress (called by Python backend, no auth)
router.post("/:botId/progress", (req, res, next) => {
    console.info("Update bot progress route accessed", {
        method: req.method,
        path: req.originalUrl,
        botId: req.params.botId,
        timestamp: new Date().toISOString()
    });
    updateBotProgress(req, res, next);
});

export default router;