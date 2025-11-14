import { login } from "../../src/controllers/authController.js";
import { logRequest, loginLimiter } from "../../src/helpers/helperFunctions.js";
import { applyMiddleware } from "../../src/middleware/applyMiddleware.js";
import { getDb } from "../../src/utils/getDb.js";

export default async function handler(req, res) {
    if (req.method !== "POST") return res.status(405).json({ message: "Method Not Allowed" });

    try {
        const db = await getDb();
        req.db = db;

        logRequest(req, res, () => { });
        await applyMiddleware(loginLimiter)(req, res);

        return login(req, res);
    } catch (error) {
        console.error("Login error:", error);
        return res.status(500).json({ message: "Internal Server Error" });
    }
}