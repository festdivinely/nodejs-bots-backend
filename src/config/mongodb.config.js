// config/mongodb.config.js
import mongoose from "mongoose";
import dotenv from "dotenv";

dotenv.config();

// Global cache for serverless
let cached = global.mongoose;

if (!cached) {
    cached = global.mongoose = { conn: null, promise: null };
}

async function connectDb() {
    if (cached.conn) return cached.conn;

    if (!process.env.MONGO_URI) {
        console.error("❌ MONGO_URI not set in environment variables");
        throw new Error("Please define MONGO_URI in .env or Vercel Environment Variables");
    }

    if (!cached.promise) {
        console.log("🔗 Connecting to MongoDB...");
        cached.promise = mongoose
            .connect(process.env.MONGO_URI, {
                serverSelectionTimeoutMS: 5000,
                maxPoolSize: 10, // serverless-friendly
            })
            .then((mongooseInstance) => {
                console.log("✅ MongoDB connected successfully");
                return mongooseInstance;
            })
            .catch((err) => {
                cached.promise = null;
                console.error("❌ MongoDB connection error:", err);
                throw err;
            });
    }

    cached.conn = await cached.promise;
    return cached.conn;
}

export default connectDb;
