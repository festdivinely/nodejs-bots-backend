// api/index.js
import app from "../src/app.js";
import connectDb from "../src/config/mongodb.config.js";

let isDbConnected = false;

export default async function handler(req, res) {
    if (!isDbConnected) {
        try {
            await connectDb();
            isDbConnected = true;
            console.info("MongoDB connected at cold start");
        } catch (error) {
            console.error("MongoDB failed:", error.message);
            return res.status(500).json({ error: "Service unavailable" });
        }
    }

    // Fix Vercel path stripping
    const path = req.url.split("?")[0];
    if (path === "/" || path === "") {
        req.url = "/";
    } else if (!path.startsWith("/api/")) {
        req.url = "/api" + path;
    }

    app(req, res);
}