import { updateBotProgress } from "../../controllers/botControllers.js";
import { getDb } from "../../utils/getDb.js";

export default async function handler(req, res) {
    if (req.method !== "POST") return res.status(405).json({ message: "Method Not Allowed" });
    await getDb();
    req.params = { botId: req.query.botId };
    return updateBotProgress(req, res);
}