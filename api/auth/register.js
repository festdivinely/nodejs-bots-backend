import { register } from "../../src/controllers/authController.js";
import { logRequest, registerLimiter } from "../../src/helpers/helperFunctions.js";
import { applyMiddleware } from "../../src/middleware/applyMiddleware.js";
import { getDb } from "../../src/utils/getDb.js";

export default async function handler(req, res) {
    if (req.method !== "POST") return res.status(405).json({ message: "Method Not Allowed" }); // Changed to POST

    try {
        const db = await getDb();
        req.db = db;

        logRequest(req, res, () => { });
        await applyMiddleware(registerLimiter)(req, res);

        return register(req, res);
    } catch (error) {
        console.error("Register error:", error);
        return res.status(500).json({ message: "Internal Server Error" });
    }
}