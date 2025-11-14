import { createBotTemplate } from "../../controllers/botControllers.js";
import { protect, requireRole } from "../../middleware/authMiddleware.js";
import { applyMiddleware } from "../../middleware/applyMiddleware.js";
import { getDb } from "../../utils/getDb.js";

export default async function handler(req, res) {
    if (req.method !== "POST") return res.status(405).json({ message: "Method Not Allowed" });
    await getDb();
    try {
        await applyMiddleware(protect)(req, res);
        await applyMiddleware(requireRole(["admin"]))(req, res);
    } catch { return res.status(403).json({ message: "Forbidden" }); }
    return createBotTemplate(req, res);
}