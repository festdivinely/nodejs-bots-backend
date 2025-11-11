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

    // THIS IS THE ONLY LINE THAT MATTERS
    req.url = req.url.replace(/^\/(auth|bots|register|login|logout|profile)/, "/api/$1");

    app(req, res);
}