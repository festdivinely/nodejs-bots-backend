// src/config/mongodb.config.js
import mongoose from "mongoose";

let cachedConnection = null;

const connectDb = async () => {
    if (cachedConnection) return cachedConnection;

    try {
        cachedConnection = await mongoose.connect(process.env.MONGO_URI);
        return cachedConnection;
    } catch (err) {
        console.error("MongoDB connection failed", err);
        throw err;
    }
};

export default connectDb;
