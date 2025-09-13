import mongoose from "mongoose";
import { logger } from "../logger/logger.js"; // Import Pino logger

const connectDb = async () => {
    try {
        const conn = await mongoose.connect(process.env.MONGO_URI);
        logger.info("MongoDB connection established", { host: conn.connection.host, timestamp: new Date().toISOString() });
    } catch (error) {
        logger.error("Failed to connect to MongoDB", { error: error.message, timestamp: new Date().toISOString() });
        process.exit(1);
    }
};

export default connectDb;