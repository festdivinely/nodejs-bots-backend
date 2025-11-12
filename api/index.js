// api/index.js
import app from "../src/app.js";
import connectDb from "../src/config/mongodb.config.js";

let isDbConnected = false;

export default async function handler(req, res) {
    // Enhanced logging that will appear in Vercel
    console.log('=== INCOMING REQUEST ===');
    console.log(`Method: ${req.method}`);
    console.log(`URL: ${req.url}`);
    console.log(`Original URL: ${req.originalUrl}`);
    console.log(`Path: ${req.path}`);
    console.log(`Headers:`, JSON.stringify(req.headers));
    console.log('========================');

    if (!isDbConnected) {
        try {
            console.log('Attempting database connection...');
            await connectDb();
            isDbConnected = true;
            console.log("✅ Database connected successfully");
        } catch (error) {
            console.error("❌ Database connection failed:", error);
            return res.status(500).json({
                success: false,
                error: "Database connection failed",
                details: error.message
            });
        }
    }

    // Add response logging
    const originalSend = res.send;
    res.send = function (data) {
        console.log(`Response sent: ${res.statusCode}`);
        if (res.statusCode >= 400) {
            console.log(`Error response:`, data);
        }
        originalSend.apply(res, arguments);
    };

    try {
        await app(req, res);
        console.log(`Request completed: ${req.method} ${req.url} - Status: ${res.statusCode}`);
    } catch (error) {
        console.error('Request error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
}