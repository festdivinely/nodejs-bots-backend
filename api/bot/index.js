import { getAllBots } from "../../controllers/botControllers.js";
import { getDb } from "../../utils/getDb.js";

export default async function handler(req, res) {
    if (req.method !== "GET") return res.status(405).json({ message: "Method Not Allowed" });
    await getDb();
    return getAllBots(req, res);
}