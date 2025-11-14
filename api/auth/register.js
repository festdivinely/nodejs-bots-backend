import { register } from "../../src/controllers/authController.js";
import { logRequest, registerLimiter } from "../../helpers/helperFunctions.js";
import { applyMiddleware } from "../../src/middleware/applyMiddleware.js";
import { getDb } from "../../src/utils/getDb.js";

export default async function handler(req, res) {
    if (req.method !== "GET") return res.status(405).json({ message: "Method Not Allowed" });
    await getDb();
    logRequest(req, res, () => { });
    try { await applyMiddleware(registerLimiter)(req, res); }
    catch { return res.status(429).json({ message: "Too many requests" }); }

    return register(req, res);
}