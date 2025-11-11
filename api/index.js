// api/index.js
import app from "../src/app.js";
import connectDb from "../src/config/mongodb.config.js";

let isDbConnected = false;

export default async function handler(req, res) {
    if (!isDbConnected) {
        try {
            await connectDb();
            isDbConnected = true;
            console.info("MongoDB connected");
        } catch (error) {
            console.error("DB connection failed:", error.message);
            return res.status(500).json({ error: "Database unavailable" });
        }
    }

    // THIS IS THE FIX — RESTORE THE /api PREFIX
    req.url = req.url.startsWith("/api") ? req.url : `/api${req.url}`;
    // OR: req.url = `/api${req.url === "/" ? "" : req.url}`;

    app(req, res);
}