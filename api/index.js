// api/index.js
export default function handler(req, res) {
    res.status(200).json({
        message: "Trade Divinely Bot API is LIVE",
        timestamp: new Date().toISOString(),
        docs: "https://quantumrobots.com/api-docs",
        routes: {
            auth: [
                "GET    /api/auth/register",
                "POST   /api/auth/login",
                "POST   /api/auth/logout",
                "POST   /api/auth/verify-device",
                "POST   /api/auth/resend-verify-device",
                "POST   /api/auth/request-password-reset",
                "POST   /api/auth/reset-password/:token",
                "POST   /api/auth/verify-email",
                "POST   /api/auth/resend-verify-email",
                "POST   /api/auth/refresh-token",
                "GET    /api/auth/profile",
                "PUT    /api/auth/profile/image",
                "PUT    /api/auth/profile/username",
                "GET    /api/auth/admin",
                "GET    /api/auth/verify-reset-token/:token"
            ],
            bot: [
                "POST   /api/bot",
                "PATCH  /api/bot/:id",
                "GET    /api/bot",
                "GET    /api/bot/user",
                "POST   /api/bot/acquire",
                "PATCH  /api/bot/:botId",
                "POST   /api/bot/:botId/start",
                "POST   /api/bot/:botId/stop",
                "DELETE /api/bot/:botId",
                "GET    /api/bot/:botId/has-api-key",
                "POST   /api/bot/:botId/progress"
            ]
        }
    });
}