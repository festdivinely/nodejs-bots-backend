// utils/getDb.js
let cachedDb = null;

export async function getDb() {
    if (cachedDb) return cachedDb;

    const client = await (await import("../config/mongodb.config.js")).default;

    // CORRECT DB NAME
    const db = client.db("trading-bot-nodejs-clau");

    cachedDb = db;
    return db;
}