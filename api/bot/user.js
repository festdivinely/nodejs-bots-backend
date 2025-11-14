// src/api/bot/user.js
import { getUserBots } from "../../controllers/botController.js";
import { protect } from "../../middleware/authMiddleware.js";
import { applyMiddleware } from "../../middleware/applyMiddleware.js";
import { getDb } from "../../src/utils/getDb.js";

export default async function handler(req, res) {
    if (req.method !== "GET") return res.status(405).json({ message: "Method Not Allowed" });

    const db = await getDb();
    req.db = db;

    try {
        await applyMiddleware(protect)(req, res);
        return getUserBots(req, res);
    } catch {
        return res.status(401).json({ message: "Unauthorized" });
    }
}