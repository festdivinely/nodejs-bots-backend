// src/api/bot/list.js
import { getAllBots } from "../../controllers/botController.js";
import { getDb } from "../../src/utils/getDb.js";

export default async function handler(req, res) {
    if (req.method !== "GET") return res.status(405).json({ message: "Method Not Allowed" });

    const db = await getDb();
    req.db = db;

    return getAllBots(req, res);
}