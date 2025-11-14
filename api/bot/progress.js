// src/api/bot/progress.js
import { updateBotProgress } from "../../controllers/botController.js";
import { getDb } from "../../src/utils/getDb.js";

export default async function handler(req, res) {
    if (req.method !== "POST") return res.status(405).json({ message: "Method Not Allowed" });

    const db = await getDb();
    const client = await (await import("../../config/db.js")).default;
    req.db = db;
    req.client = client;

    return updateBotProgress(req, res);
}