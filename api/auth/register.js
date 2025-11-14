// src/api/auth/register.js
import { register } from "../../controllers/authController.js";
import { logRequest, registerLimiter } from "../../helpers/helperFunctions.js";
import { applyMiddleware } from "../../middleware/applyMiddleware.js";
import { getDb } from "../../src/utils/getDb.js";

export default async function handler(req, res) {
    if (req.method !== "GET") return res.status(405).json({ message: "Method Not Allowed" });

    const db = await getDb();
    req.db = db;

    logRequest(req, res, () => { });
    try { await applyMiddleware(registerLimiter)(req, res); }
    catch { return res.status(429).json({ message: "Too many requests" }); }

    return register(req, res);
}