import { updateBotTemplate } from "../../controllers/botControllers.js";
import { protect, requireRole } from "../../middleware/authMiddleware.js";
import { applyMiddleware } from "../../middleware/applyMiddleware.js";
import { getDb } from "../../src/utils/getDb.js";

export default async function handler(req, res) {
    if (req.method !== "PATCH") return res.status(405).json({ message: "Method Not Allowed" });
    await getDb();
    req.params = { id: req.query.id };
    try {
        await applyMiddleware(protect)(req, res);
        await applyMiddleware(requireRole(["admin"]))(req, res);
    } catch { return res.status(403).json({ message: "Forbidden" }); }
    return updateBotTemplate(req, res);
}