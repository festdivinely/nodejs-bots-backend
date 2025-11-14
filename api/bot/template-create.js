// src/api/bot/create.js
import { createBotTemplate } from "../../controllers/botController.js";
import { protect, requireRole } from "../../middleware/authMiddleware.js";
import { applyMiddleware } from "../../middleware/applyMiddleware.js";
import { getDb } from "../../src/utils/getDb.js";

export default async function handler(req, res) {
    if (req.method !== "POST") return res.status(405).json({ message: "Method Not Allowed" });

    const db = await getDb();
    const client = await (await import("../../config/db.js")).default;
    req.db = db;
    req.client = client;

    try {
        await applyMiddleware(protect)(req, res);
        await applyMiddleware(requireRole(["admin"]))(req, res);
        return createBotTemplate(req, res);
    } catch {
        return res.status(403).json({ message: "Forbidden" });
    }
}