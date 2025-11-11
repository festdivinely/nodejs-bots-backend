// api/index.js
import app from "../src/app.js";
import connectDb from "../src/config/mongodb.config.js";

let isDbConnected = false;

export default async function handler(req, res) {
    // Connect DB once
    if (!isDbConnected) {
        try {
            await connectDb();
            isDbConnected = true;
            console.info("MongoDB connected");
        } catch (error) {
            console.error("DB connection failed:", error);
            return res.status(500).json({ error: "Database unavailable" });
        }
    }

    // PERFECT FIX: Only add /api if request is NOT root AND doesn't already start with /api
    const originalUrl = req.url || "/";

    if (originalUrl === "/" || originalUrl === "") {
        // Root → let Express handle it (your HTML page)
        req.url = "/";
    } else if (!originalUrl.startsWith("/api")) {
        // API route → add /api prefix
        req.url = `/api${originalUrl}`;
    }
    // If already starts with /api → leave it (e.g. /api/auth)

    app(req, res);
}