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
        pass: EMAIL_PASSWORD,
    },
});

export async function sendVerificationEmail(receiverEmail, verificationLink, token) {
    /**
     * Send a verification email with a token to the specified receiver.
     * Includes a copy button for the token and instructions to paste it in the app.
     * Returns true if the email was sent successfully, false otherwise.
     */
    try {
        // Validate environment variables
        if (EMAIL_SENDER === 'no-email-set' || EMAIL_PASSWORD === 'no-password-set') {
            logger.error('Email sender or password not set in environment variables', { timestamp: new Date().toISOString() });
            throw new Error('Email sender or password not set in environment variables');
        }

        // Email content
        const subject = 'Verify Your Email - Trade Divinely Bot';
        const plainBody = `
      Welcome to Trade Divinely Bot 🎉

      To verify your email, please copy the following token and paste it into the Verify Email screen in the Trade Divinely Bot app:

      Token: ${token}

      This token will expire in 30 minutes for your security.
      If you didn't register, please ignore this email.
    `;
        const htmlBody = `
      <html>
      <body style="margin:0; padding:0; font-family: Arial, sans-serif; background-color:#f4f7fb;">
        <table width="100%" border="0" cellspacing="0" cellpadding="0" style="padding:20px 0;">
          <tr>
            <td align="center">
              <!-- Card -->
              <table width="600" border="0" cellspacing="0" cellpadding="0" 
                style="background:#ffffff; border-radius:12px; box-shadow:0 4px 12px rgba(0,0,0,0.1); overflow:hidden;">
                
                <!-- Header -->
                <tr>
                  <td align="center" 
                    style="background: linear-gradient(90deg, #4facfe 0%, #00f2fe 100%); 
                      padding:30px; color:#ffffff; font-size:24px; font-weight:bold;">
                    Trade Divinely Bot 🎉
                  </td>
                </tr>

                <!-- Body -->
                <tr>
                  <td style="padding:30px; color:#333333; font-size:16px; line-height:1.6;">
                    <h2 style="margin-top:0; color:#4facfe;">Welcome!</h2>
                    <p>
                      We're excited to have you join <b>Trade Divinely Bot</b>.  
                      To verify your email address, please copy the token below and paste it into the Verify Email screen in the Trade Divinely Bot app.
                    </p>
                    
                    <!-- Token and Copy Button -->
                    <p style="text-align:center; margin:30px 0;">
                      <span style="font-size:18px; background:#f0f0f0; padding:10px 20px; border-radius:6px; display:inline-block; user-select:all; -webkit-user-select:all; -moz-user-select:all;">
                        ${token}
                      </span>
                      <br/>
                      <button onclick="try { navigator.clipboard.writeText('${token}'); alert('Token copied to clipboard!'); } catch(e) { alert('Please manually copy the token.'); }" 
                        style="background:#4facfe; color:#ffffff; text-decoration:none; 
                               padding:10px 20px; border-radius:6px; font-size:14px; font-weight:bold; 
                               display:inline-block; margin-top:10px; cursor:pointer; border:none;">
                        📋 Copy Token
                      </button>
                    </p>

                    <p>
                      <strong>Instructions:</strong> Open the Trade Divinely Bot app, go to the Verify Email screen, and paste the token. 
                      If the copy button doesn't work, tap and hold the token above to copy it manually.
                      This token will expire in <b>30 minutes</b> for your security.
                    </p>

                    <p>
                      If you didn’t sign up for Trade Divinely Bot, you can safely ignore this email.
                    </p>
                  </td>
                </tr>

                <!-- Footer -->
                <tr>
                  <td align="center" 
                    style="background:#f4f7fb; padding:20px; font-size:13px; color:#888888;">
                    &copy; ${new Date().getFullYear()} Trade Divinely Bot. All rights reserved.<br/>
                    Need help? <a href="mailto:support@tradedivinely.com" style="color:#4facfe; text-decoration:none;">Contact Support</a>
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
            html: htmlBody,
        });

        logger.info(`Verification email sent successfully`, { receiverEmail, timestamp: new Date().toISOString() });
        return true;
    } catch (error) {
        if (error.code === 'EAUTH') {
            logger.error('Authentication failed. Check your email and App Password.', {
                receiverEmail,
                error: error.message,
                timestamp: new Date().toISOString(),
            });
        } else {
            logger.error(`Failed to send verification email`, {
                receiverEmail,
                error: error.message,
                timestamp: new Date().toISOString(),
            });
        }
        return false;
    }
}
