// config/mongodb.config.js
import mongoose from "mongoose";
import dotenv from "dotenv";

dotenv.config();

async function connectDb() {
    if (!process.env.MONGO_URI) {
        console.error("❌ MONGO_URI not set in environment variables");
        throw new Error("Please define MONGO_URI in .env or Vercel Environment Variables");
    }

    try {
        // Only connect if not already connected
        if (mongoose.connection.readyState === 0) {
            console.log("🔗 Connecting to MongoDB...");
            await mongoose.connect(process.env.MONGO_URI, {
                maxPoolSize: 5, // reasonable limit for serverless
                connectTimeoutMS: 60000,
                socketTimeoutMS: 60000,
                serverSelectionTimeoutMS: 60000,
            });
            console.log("✅ MongoDB connected successfully");
        } else {
            console.log("⚡ MongoDB already connected");
        }
    } catch (err) {
        console.error("❌ MongoDB connection failed:", err.message);
        throw err;
    }
}

export default connectDb;

