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
                "POST   /api/auth/request-password-reset",
                "POST   /api/auth/reset-password/:token",
                "POST   /api/auth/verify-email",
                "POST   /api/auth/resend-verify-email",
                "POST   /api/auth/refresh-token",
                "GET    /api/auth/profile",
                "GET    /api/auth/admin",
                "GET    /api/auth/verify-reset-token/:token"
            ],
        }
    });
}