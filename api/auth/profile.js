import { getProfile } from "../../controllers/authController.js";
import { logRequest } from "../../helpers/helperFunctions.js";
import { protect } from "../../middleware/authMiddleware.js";
import { applyMiddleware } from "../../middleware/applyMiddleware.js";
import { getDb } from "../../utils/getDb.js";

export default async function handler(req, res) {
    if (req.method !== "GET") return res.status(405).json({ message: "Method Not Allowed" });
    await getDb();
    logRequest(req, res, () => { });
    try { await applyMiddleware(protect)(req, res); }
    catch { return res.status(401).json({ message: "Unauthorized" }); }

    return getProfile(req, res);
}