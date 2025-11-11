import mongoose from "mongoose";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

let cached = global.mongoose;

if (!cached) {
    cached = global.mongoose = { conn: null, promise: null };
}

async function connectDb() {
    if (cached.conn) return cached.conn;

    if (!cached.promise) {
        console.log("Connecting to MongoDB...");
        cached.promise = mongoose
            .connect(process.env.MONGO_URI, {
                useNewUrlParser: true,
                useUnifiedTopology: true,
            })
            .then((mongoose) => {
                console.log("MongoDB connection established", {
                    host: mongoose.connection.host,
                    port: mongoose.connection.port,
                });
                return mongoose;
            })
            .catch((err) => {
                console.error("MongoDB connection failed:", err.message);
                throw err;
            });
    }

    cached.conn = await cached.promise;
    return cached.conn;
}

export default connectDb;
