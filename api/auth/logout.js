import { logout } from "../../controllers/authController.js";
import { logRequest } from "../../helpers/helperFunctions.js";
import { protect, csrfProtect } from "../../middleware/authMiddleware.js";
import { applyMiddleware } from "../../middleware/applyMiddleware.js";
import { getDb } from "../../utils/getDb.js";

export default async function handler(req, res) {
    if (req.method !== "POST") return res.status(405).json({ message: "Method Not Allowed" });
    await getDb();
    logRequest(req, res, () => { });
    try {
        await applyMiddleware(protect)(req, res);
        await applyMiddleware(csrfProtect)(req, res);
    } catch (err) { return res.status(401).json({ message: err.message || "Unauthorized" }); }

    return logout(req, res);
}