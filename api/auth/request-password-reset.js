import { requestPasswordReset } from "../../controllers/authController.js";
import { logRequest, resetLimiter } from "../../helpers/helperFunctions.js";
import { applyMiddleware } from "../../middleware/applyMiddleware.js";
import { getDb } from "../../src/utils/getDb.js";

export default async function handler(req, res) {
    if (req.method !== "POST") return res.status(405).json({ message: "Method Not Allowed" });
    await getDb();
    logRequest(req, res, () => { });
    try { await applyMiddleware(resetLimiter)(req, res); }
    catch { return res.status(429).json({ message: "Too many requests" }); }

    return requestPasswordReset(req, res);
}