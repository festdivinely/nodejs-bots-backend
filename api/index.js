// api/index.js
import app from "../src/app.js";
import connectDb from "../src/config/mongodb.config.js";

// Global flag to track connection (survives warm invocations)
let isDbConnected = false;

export default async function handler(req, res) {
    // Connect to MongoDB only once (or on cold start)
    if (!isDbConnected) {
        try {
            await connectDb();
            isDbConnected = true;
            console.info("MongoDB connected successfully in Vercel function");
        } catch (error) {
            console.error("Failed to connect to MongoDB:", error.message);
            // Don't crash — let request fail gracefully
            return res.status(500).json({ error: "Database connection failed" });
        }
    }

    // Let your Express app handle the request
    app(req, res);
}