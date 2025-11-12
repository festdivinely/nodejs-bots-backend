// config/mongodb.config.js
import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config();

let cached = global.mongoose;

if (!cached) {
    cached = global.mongoose = { conn: null, promise: null };
}

async function connectDb() {
    if (cached.conn) {
        return cached.conn;
    }

    if (!process.env.MONGO_URI) {
        console.error("MONGO_URI not set in environment variables");
        throw new Error("Please define MONGO_URI in .env or Vercel");
    }

    if (!cached.promise) {
        console.log("Connecting to MongoDB...");
        cached.promise = mongoose.connect(process.env.MONGO_URI, {
            useNewUrlParser: true,
            serverSelectionTimeoutMS: 5000,
            maxPoolSize: 10, // Important for serverless
        }).then((mongoose) => {
            console.log("MongoDB connected successfully");
            return mongoose;
        });
    }

    try {
        cached.conn = await cached.promise;
        return cached.conn;
    } catch (e) {
        cached.promise = null;
        throw e;
    }
}

export default connectDb;