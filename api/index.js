// api/index.js
import app from "../src/app.js";
import connectDb from "../src/config/mongodb.config.js";

let isDbConnected = false;

export default async function handler(req, res) {
    if (!isDbConnected) {
        try {
            await connectDb();
            isDbConnected = true;
        } catch (error) {
            console.error("Database connection failed:", error);
            return res.status(500).json({ error: "Database connection failed" });
        }
    }

    // Remove the URL rewriting logic - it's causing issues
    // Let Express handle the routing directly

    return app(req, res);
}