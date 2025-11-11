import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import { logger } from '../logger/logger.js'; // Import Pino logger

// Load environment variables
dotenv.config();

// Retrieve environment variables (reuse from your existing files)
const EMAIL_SENDER = process.env.EMAIL_SENDER || 'no-email-set';
const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD || 'no-password-set';
const SMTP_SERVER = 'smtp.gmail.com';
const SMTP_PORT = 465;

// Configure nodemailer transporter (identical to your existing)
const transporter = nodemailer.createTransport({
    host: SMTP_SERVER,
    port: SMTP_PORT,
    secure: true, // true for 465 (SSL)
    auth: {
        user: EMAIL_SENDER,
        pass: EMAIL_PASSWORD
    }
});

export async function sendSuspiciousActivityEmail(receiverEmail, activityData) {
    /**
     * Send a suspicious activity alert email to the specified receiver.
     * activityData: { ip, country, deviceInfo, message } (from controller).
     * Returns true if the email was sent successfully, false otherwise.
     */
    try {
        // Validate environment variables
        if (EMAIL_SENDER === 'no-email-set' || EMAIL_PASSWORD === 'no-password-set') {
            console.error('Email sender or password not set in environment variables', { timestamp: new Date().toISOString() });
            throw new Error('Email sender or password not set in environment variables');
        }

        // Destructure activity data with fallbacks
        const { ip = 'Unknown', country = 'Unknown', deviceInfo = 'Unknown device', message = 'Suspicious activity detected' } = activityData || {};

        // Email content
        const subject = 'Security Alert: Suspicious Activity on Your Trade Divinely Bot Account';
        const plainBody = `
            We detected unusual activity on your Trade Divinely Bot account. Details:
            - IP Address: ${ip}
            - Location: ${country}
            - Device: ${deviceInfo}
            - Activity: ${message}

            If this was you, you can ignore this email. If not, please secure your account immediately:
            1. Log in and change your password.
            2. Review your recent sessions and log out from unknown devices.
            3. Enable two-factor authentication (2FA) if not already active.

            If you didn't recognize this activity, contact support@tradedivinely.com right away.

            Thank you,
            The Trade Divinely Bot Team
        `;

        const htmlBody = `
            <html>
            <body style="margin:0; padding:0; font-family: Arial, sans-serif; background-color:#f4f7fb;">
                <table width="100%" border="0" cellspacing="0" cellpadding="0" style="padding:20px 0;">
                    <tr>
                        <td align="center">
                            <!-- Card -->
                            <table width="600" border="0" cellspacing="0" cellpadding="0" style="background:#ffffff; border-radius:12px; box-shadow:0 4px 12px rgba(0,0,0,0.1); overflow:hidden;">
                                <!-- Header -->
                                <tr>
                                    <td align="center" style="background: linear-gradient(90deg, #ff6b6b 0%, #ff8e53 100%); padding:30px; color:#ffffff; font-size:24px; font-weight:bold;">
                                        Trade Divinely Bot Security Alert
                                    </td>
                                </tr>
                                <!-- Body -->
                                <tr>
                                    <td style="padding:30px; color:#333333; font-size:16px; line-height:1.6;">
                                        <h2 style="margin-top:0; color:#ff6b6b;">Unusual Activity Detected</h2>
                                        <p>
                                            We noticed something unusual on your <b>Trade Divinely Bot</b> account. Here's what we detected:
                                        </p>
                                        <ul style="margin:20px 0; padding-left:20px;">
                                            <li><strong>IP Address:</strong> ${ip}</li>
                                            <li><strong>Location:</strong> ${country}</li>
                                            <li><strong>Device:</strong> ${deviceInfo}</li>
                                            <li><strong>Activity:</strong> ${message}</li>
                                        </ul>
                                        <p>
                                            If this was you, no action is needed. If not, secure your account now:
                                        </p>
                                        <ul style="margin:20px 0; padding-left:20px;">
                                            <li>Log in and change your password immediately.</li>
                                            <li>Review active sessions and log out from unknown devices.</li>
                                            <li>Enable two-factor authentication (2FA) for extra protection.</li>
                                        </ul>
                                        <!-- Button -->
                                        <p style="text-align:center; margin:30px 0;">
                                            <a href="${process.env.FRONTEND_URL}/login" style="background: #ff6b6b; color:#ffffff; text-decoration:none; padding:14px 28px; border-radius:6px; font-size:16px; font-weight:bold; display:inline-block;">
                                                Secure Your Account
                                            </a>
                                        </p>
                                        <p>
                                            For help, <a href="mailto:support@tradedivinely.com" style="color:#ff6b6b; text-decoration:none;">contact support</a>.
                                        </p>
                                    </td>
                                </tr>
                                <!-- Footer -->
                                <tr>
                                    <td align="center" style="background:#f4f7fb; padding:20px; font-size:13px; color:#888888;">
                                        &copy; ${new Date().getFullYear()} Trade Divinely Bot. All rights reserved.<br/>
                                        This is an automated security notification. Do not reply.
                                    </td>
                                </tr>
                            </table>
                            <!-- End Card -->
                        </td>
                    </tr>
                </table>
            </body>
            </html>
        `;

        // Send email
        await transporter.sendMail({
            from: EMAIL_SENDER,
            to: receiverEmail,
            subject: subject,
            text: plainBody,
            html: htmlBody
        });

        console.info('Suspicious activity email sent successfully', { receiverEmail, ip, country, timestamp: new Date().toISOString() });
        return true;
    } catch (error) {
        if (error.code === 'EAUTH') {
            console.error('Authentication failed. Check your email and App Password.', {
                receiverEmail,
                error: error.message,
                timestamp: new Date().toISOString()
            });
        } else {
            console.error('Failed to send suspicious activity email', {
                receiverEmail,
                error: error.message,
                timestamp: new Date().toISOString()
            });
        }
        return false;
    }
}