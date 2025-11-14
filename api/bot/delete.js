// src/api/bot/delete.js
import { deleteUserBot } from "../../controllers/botController.js";
import { protect } from "../../middleware/authMiddleware.js";
import { applyMiddleware } from "../../middleware/applyMiddleware.js";
import { getDb } from "../../src/utils/getDb.js";

export default async function handler(req, res) {
    if (req.method !== "DELETE") return res.status(405).json({ message: "Method Not Allowed" });

    const db = await getDb();
    const client = await (await import("../../config/db.js")).default;
    req.db = db;
    req.client = client;

    try {
        await applyMiddleware(protect)(req, res);
        return deleteUserBot(req, res);
    } catch {
        return res.status(401).json({ message: "Unauthorized" });
    }
}