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
            return res.status(500).json({ error: "DB failed" });
        }
    }

    // PERFECT URL NORMALIZATION
    if (!req.url.startsWith('/api/') && !req.url.startsWith('/api')) {
        if (req.url.startsWith('/auth') || req.url.startsWith('/bots')) {
            req.url = '/api' + req.url;
        } else if (req.url === '/' || req.url === '') {
            req.url = '/api';
        }
    }

    app(req, res);
}