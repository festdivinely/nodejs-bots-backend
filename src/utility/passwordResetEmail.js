import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import { logger } from '../logger/logger.js'; // Import Pino logger

// Load environment variables
dotenv.config();

// Retrieve environment variables
const EMAIL_SENDER = process.env.EMAIL_SENDER || 'no-email-set';
const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD || 'no-password-set';
const SMTP_SERVER = 'smtp.gmail.com';
const SMTP_PORT = 465;
const SECURITY = 'SSL';

// Configure nodemailer transporter
const transporter = nodemailer.createTransport({
    host: SMTP_SERVER,
    port: SMTP_PORT,
    secure: true, // true for 465 (SSL)
    auth: {
        user: EMAIL_SENDER,
        pass: EMAIL_PASSWORD
    }
});

export async function sendPasswordResetEmail(receiverEmail, resetLink) {
    /**
     * Send a password reset email to the specified receiver.
     * Returns true if the email was sent successfully, false otherwise.
     */
    try {
        // Validate environment variables
        if (EMAIL_SENDER === 'no-email-set' || EMAIL_PASSWORD === 'no-password-set') {
            logger.error('Email sender or password not set in environment variables', { timestamp: new Date().toISOString() });
            throw new Error('Email sender or password not set in environment variables');
        }

        // Email content
        const subject = 'Reset Your Password - Trade Divinely Bot';
        const plainBody = `You requested a password reset for Trade Divinely Bot. Please reset your password by clicking the link below:\n${resetLink}\nThis link will expire in 15 minutes for your security.\nIf you didn’t request a password reset, please ignore this email or contact support.`;

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
                      Trade Divinely Bot 🔒
                    </td>
                  </tr>
                  <!-- Body -->
                  <tr>
                    <td style="padding:30px; color:#333333; font-size:16px; line-height:1.6;">
                      <h2 style="margin-top:0; color:#ff6b6b;">Password Reset Request</h2>
                      <p>
                        We received a request to reset your password for <b>Trade Divinely Bot</b>. To proceed, please click the button below to set a new password.
                      </p>
                      <!-- Button -->
                      <p style="text-align:center; margin:30px 0;">
                        <a href="${resetLink}" style="background: #ff6b6b; color:#ffffff; text-decoration:none; padding:14px 28px; border-radius:6px; font-size:16px; font-weight:bold; display:inline-block;">
                          🔄 Reset Password
                        </a>
                      </p>
                      <p>
                        This link will expire in <b>15 minutes</b> for your security. If you didn’t request a password reset, please ignore this email or <a href="mailto:support@tradedivinely.com" style="color:#ff6b6b; text-decoration:none;">contact our support team</a>.
                      </p>
                    </td>
                  </tr>
                  <!-- Footer -->
                  <tr>
                    <td align="center" style="background:#f4f7fb; padding:20px; font-size:13px; color:#888888;">
                      &copy; ${new Date().getFullYear()} Trade Divinely Bot. All rights reserved.<br/>
                      Need help? <a href="mailto:support@tradedivinely.com" style="color:#ff6b6b; text-decoration:none;">Contact Support</a>
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

        logger.info('Password reset email sent successfully', { receiverEmail, timestamp: new Date().toISOString() });
        return true;
    } catch (error) {
        if (error.code === 'EAUTH') {
            logger.error('Authentication failed. Check your email and App Password.', {
                receiverEmail,
                error: error.message,
                timestamp: new Date().toISOString()
            });
        } else {
            logger.error('Failed to send password reset email', {
                receiverEmail,
                error: error.message,
                timestamp: new Date().toISOString()
            });
        }
        return false;
    }
}