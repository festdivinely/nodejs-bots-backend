// config/db.js
import { MongoClient } from "mongodb";
import dotenv from "dotenv";

dotenv.config();

let client;
let clientPromise;

if (!process.env.MONGO_URI) {
    throw new Error("Please add your MONGO_URI to .env.local or Vercel");
}

if (process.env.NODE_ENV === "development") {
    // In dev: reuse connection
    if (!global._mongoClientPromise) {
        client = new MongoClient(process.env.MONGO_URI);
        global._mongoClientPromise = client.connect();
    }
    clientPromise = global._mongoClientPromise;
} else {
    // In production (Vercel): reuse across Lambda instances
    client = new MongoClient(process.env.MONGO_URI);
    clientPromise = client.connect();
}

export default clientPromise;