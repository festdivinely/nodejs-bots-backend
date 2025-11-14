// api/index.js
export default function handler(req, res) {
    res.status(200).json({
        message: "Trade Divinely Bot API is LIVE",
        timestamp: new Date().toISOString(),
        docs: "https://quantumrobots.com/api-docs"
    });
}