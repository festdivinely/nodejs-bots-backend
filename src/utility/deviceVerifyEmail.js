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

export async function sendDeviceVerificationEmail(receiverEmail, otp, deviceInfo, ip) {
    /**
     * Send a device verification OTP email to the specified receiver.
     * otp: 6-character code from userModel.js.
     * deviceInfo and ip: For context (from controller).
     * Returns true if the email was sent successfully, false otherwise.
     */
    try {
        // Validate environment variables
        if (EMAIL_SENDER === 'no-email-set' || EMAIL_PASSWORD === 'no-password-set') {
            logger.error('Email sender or password not set in environment variables', { timestamp: new Date().toISOString() });
            throw new Error('Email sender or password not set in environment variables');
        }

        // Fallbacks for deviceInfo and ip
        const safeDeviceInfo = deviceInfo || 'Unknown device';
        const safeIp = ip || 'Unknown IP';

        // Email content
        const subject = 'Verify New Device - Trade Divinely Bot';
        const plainBody = `
            We detected a new device trying to access your Trade Divinely Bot account. To verify, use this one-time password (OTP):

            OTP: ${otp}

            Details:
            - Device: ${safeDeviceInfo}
            - IP Address: ${safeIp}

            This OTP expires in 5 minutes. Enter it in the app to continue.

            If you didn't initiate this, ignore or contact support@tradedivinely.com to secure your account.

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
                                    <td align="center" style="background: linear-gradient(90deg, #4facfe 0%, #00f2fe 100%); padding:30px; color:#ffffff; font-size:24px; font-weight:bold;">
                                        Trade Divinely Bot 🔐 Device Verification
                                    </td>
                                </tr>
                                <!-- Body -->
                                <tr>
                                    <td style="padding:30px; color:#333333; font-size:16px; line-height:1.6;">
                                        <h2 style="margin-top:0; color:#4facfe;">New Device Detected</h2>
                                        <p>
                                            A new device is trying to log in to your <b>Trade Divinely Bot</b> account. To verify, use the one-time password (OTP) below.
                                        </p>
                                        <!-- OTP Display -->
                                        <div style="text-align:center; margin:30px 0; background:#f8f9fa; padding:20px; border-radius:8px; border:2px solid #4facfe;">
                                            <h1 style="margin:0; font-size:36px; color:#4facfe; letter-spacing:5px;">${otp}</h1>
                                            <p style="margin:10px 0 0; color:#666; font-size:14px;">This OTP expires in 5 minutes</p>
                                        </div>
                                        <p>
                                            Details of the login attempt:
                                        </p>
                                        <ul style="margin:20px 0; padding-left:20px;">
                                            <li><strong>Device:</strong> ${safeDeviceInfo}</li>
                                            <li><strong>IP Address:</strong> ${safeIp}</li>
                                        </ul>
                                        <p>
                                            Enter this OTP in the app to complete verification. If you didn't attempt this login, ignore the email or <a href="mailto:support@tradedivinely.com" style="color:#4facfe; text-decoration:none;">contact support</a> to secure your account.
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

        logger.info('Device verification email sent successfully', { receiverEmail, otp: otp.substring(0, 2) + '...', ip: safeIp, timestamp: new Date().toISOString() });
        return true;
    } catch (error) {
        if (error.code === 'EAUTH') {
            logger.error('Authentication failed. Check your email and App Password.', {
                receiverEmail,
                error: error.message,
                timestamp: new Date().toISOString()
            });
        } else {
            logger.error('Failed to send device verification email', {
                receiverEmail,
                error: error.message,
                timestamp: new Date().toISOString()
            });
        }
        return false;
    }
}