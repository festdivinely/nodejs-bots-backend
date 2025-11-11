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
            console.info("MongoDB connected in Vercel");
        } catch (error) {
            console.error("DB connection failed:", error);
            return res.status(500).json({ error: "Service unavailable" });
        }
    }

    // THE ULTIMATE FIX: Force correct path for ALL requests
    const path = req.url.split("?")[0]; // Remove query params

    // If request is to /api/auth/register but Vercel stripped /api
    if (path.startsWith("/auth") || path.startsWith("/bots") || path.startsWith("/register") || path.startsWith("/login")) {
        req.url = `/api${path}`;
    }
    // Root route
    else if (path === "/" || path === "") {
        req.url = "/";
    }
    // Fallback: add /api to anything that looks like an API call
    else if (!path.startsWith("/api") && path.includes("/")) {
        req.url = `/api${path}`;
    }

    console.info("Vercel → Express URL fix", { original: req.url, fixed: req.url });

    app(req, res);
}