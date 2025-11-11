import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Retrieve environment variables
const EMAIL_SENDER = process.env.EMAIL_SENDER || 'no-email-set';
const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD || 'no-password-set';
const SMTP_SERVER = 'smtp.gmail.com';
const SMTP_PORT = 465;

// Configure nodemailer transporter
const transporter = nodemailer.createTransport({
  host: SMTP_SERVER,
  port: SMTP_PORT,
  secure: true,
  auth: {
    user: EMAIL_SENDER,
    pass: EMAIL_PASSWORD,
  },
});

export async function sendVerificationEmail(receiverEmail, verificationLink, token) {
  try {
    if (EMAIL_SENDER === 'no-email-set' || EMAIL_PASSWORD === 'no-password-set') {
      console.error('Email sender or password not set', { timestamp: new Date().toISOString() });
      throw new Error('Email sender or password not set');
    }

    const subject = 'Verify Your Email - Trade Divinely Bot';
    const plainBody = `
      Welcome to Trade Divinely Bot

      To verify your email, tap and hold the following token to select and copy it, then paste it into the Verify Email screen in the app:

      Token: ${token}

      This token expires in 15 minutes. If you didn't register, ignore this email.
    `;
    const htmlBody = `
      <html>
      <body style="margin:0; padding:0; font-family: Arial, sans-serif; background-color:#f4f7fb;">
        <table width="100%" border="0" cellspacing="0" cellpadding="0" style="padding:20px 0;">
          <tr>
            <td align="center">
              <table width="600" border="0" cellspacing="0" cellpadding="0" 
                style  style="background:#ffffff; border-radius:12px; box-shadow:0 4px 12px rgba(0,0,0,0.1); overflow:hidden;">
                
                <tr>
                  <td align="center" 
                    style="background: linear-gradient(90deg, #4facfe 0%, #00f2fe 100%); 
                      padding:30px; color:#ffffff; font-size:24px; font-weight:bold;">
                    Trade Divinely Bot
                  </td>
                </tr>

                <tr>
                  <td style="padding:30px; color:#333333; font-size:16px; line-height:1.6;">
                    <h2 style="margin-top:0; color:#4facfe;">Welcome!</h2>
                    <p>
                      To verify your email, tap the token below to select it (on mobile, tap and hold to copy), then paste it into the Verify Email screen in the app.
                    </p>
                    
                    <p style="text-align:center; margin:30px 0;">
                      <span style="font-size:18px; background:#f0f0f0; padding:15px 25px; border-radius:8px; display:inline-block; user-select:all; -webkit-user-select:all; -moz-user-select:all; cursor:pointer; font-weight:bold;">
                        ${token}
                      </span>
                    </p>

                    <p>
                      This token expires in <b>15 minutes</b>. Open the Trade Divinely Bot app and go to the Verify Email screen to paste it.
                      If you didn’t sign up, ignore this email.
                    </p>
                  </td>
                </tr>

                <tr>
                  <td align="center" 
                    style="background:#f4f7fb; padding:20px; font-size:13px; color:#888888;">
                    &copy; ${new Date().getFullYear()} Trade Divinely Bot. All rights reserved.<br/>
                    Need help? <a href="mailto:support@tradedivinely.com" style="color:#4facfe; text-decoration:none;">Contact Support</a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
      </html>
    `;

    await transporter.sendMail({
      from: EMAIL_SENDER,
      to: receiverEmail,
      subject: subject,
      text: plainBody,
      html: htmlBody,
    });

    console.info(`Verification email sent`, { receiverEmail, timestamp: new Date().toISOString() });
    return true;
  } catch (error) {
    console.error(`Failed to send verification email`, {
      receiverEmail,
      error: error.message,
      timestamp: new Date().toISOString(),
    });
    return false;
  }
}