// routes/botRoute.js
import express from "express";
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
import { protect, requireRole } from "../middleware/authMiddleware.js";
import { logRequest } from "../helpers/helperFunctions.js";

const router = express.Router();

// Admin only routes
router.post("/", logRequest, protect, requireRole(["admin"]), createBotTemplate);
router.patch("/:id", logRequest, protect, requireRole(["admin"]), updateBotTemplate);

// Public route (get all available bots)
router.get("/", getAllBots);

// Protected user routes
router.get("/user", logRequest, protect, getUserBots);
router.post("/acquire", logRequest, protect, acquireBot);
router.patch("/:botId", logRequest, protect, updateUserBot);
router.post("/:botId/start", logRequest, protect, startUserBot);
router.post("/:botId/stop", logRequest, protect, stopUserBot);
router.delete("/:botId", logRequest, protect, deleteUserBot);

// Progress update (might be called by external services, adjust auth as needed)
router.post("/:botId/progress", updateBotProgress);

export default router;