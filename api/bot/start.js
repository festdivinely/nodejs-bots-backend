import { startUserBot } from "../../controllers/botControllers.js";
import { protect } from "../../middleware/authMiddleware.js";
import { applyMiddleware } from "../../middleware/applyMiddleware.js";
import { getDb } from "../../utils/getDb.js";

export default async function handler(req, res) {
    if (req.method !== "POST") return res.status(405).json({ message: "Method Not Allowed" });
    await getDb();
    req.params = { botId: req.query.botId };
    try { await applyMiddleware(protect)(req, res); }
    catch { return res.status(401).json({ message: "Unauthorized" }); }
    return startUserBot(req, res);
}