import app from "../src/app.js";
import connectDb from "../src/config/mongodb.config.js";

let isDbConnected = false;

export default async function handler(req, res) {
    if (!isDbConnected) {
        await connectDb();
        isDbConnected = true;
    }

    app(req, res);
}
