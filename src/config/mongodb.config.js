import mongoose from "mongoose";
import { logger } from "../logger/logger.js";

let cached = global.mongoose;

if (!cached) {
    cached = global.mongoose = { conn: null, promise: null };
}

async function connectDb() {
    if (cached.conn) return cached.conn;

    if (!cached.promise) {
        logger.info("Connecting to MongoDB...");
        cached.promise = mongoose
            .connect(process.env.MONGO_URI, {
                useNewUrlParser: true,
                useUnifiedTopology: true,
            })
            .then((mongoose) => {
                logger.info("MongoDB connection established", {
                    host: mongoose.connection.host,
                    port: mongoose.connection.port,
                });
                return mongoose;
            })
            .catch((err) => {
                logger.error("MongoDB connection failed", { error: err.message });
                throw err;
            });
    }

    cached.conn = await cached.promise;
    return cached.conn;
}

export default connectDb;
