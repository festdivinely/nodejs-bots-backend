import { login } from "../../src/controllers/authController.js";
import { logRequest, loginLimiter } from "../../src/helpers/helperFunctions.js";
import { applyMiddleware } from "../../src/middleware/applyMiddleware.js";
import { getDb } from "../../src/utils/getDb.js";

export default async function handler(req, res) {
    // Only allow POST
    if (req.method !== "POST") {
        return res.status(405).json({ message: "Method Not Allowed" });
    }

    // Connect to DB
    const db = await getDb();
    req.db = db;

    // Log request
    logRequest(req, res, () => { });

    // Apply rate limiter
    try {
        await applyMiddleware(loginLimiter)(req, res);
    } catch (err) {
        return res.status(429).json({ message: "Too many requests" });
    }

    // Call the controller
    return login(req, res);
}
