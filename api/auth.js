import app from "../src/app.js";      // your existing Express app
import connectDb from "../src/config/mongodb.config.js";

let isDbConnected = false;

export default async function handler(req, res) {
    // Ensure MongoDB connection is established (cached)
    if (!isDbConnected) {
        await connectDb();
        isDbConnected = true;
    }

    // Call Express app to handle the request
    app(req, res);
}
