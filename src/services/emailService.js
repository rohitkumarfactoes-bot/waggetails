const nodemailer = require("nodemailer");
const crypto = require("crypto");

const CONFIG = {
    IS_PRODUCTION: process.env.NODE_ENV === "production",
    OTP_VALIDITY_MS: 10 * 60 * 1000,
    EMAIL_FROM: process.env.EMAIL_FROM || "noreply@waggetail.com",
};

const logger = {
    info: (msg, meta = {}) => {
        console.log(
            JSON.stringify({
                level: "info",
                message: msg,
                timestamp: new Date().toISOString(),
                ...meta,
            })
        );
    },
    error: (msg, meta = {}) => {
        console.error(
            JSON.stringify({
                level: "error",
                message: msg,
                timestamp: new Date().toISOString(),
                ...meta,
            })
        );
    },
};

const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: process.env.EMAIL_PORT == 465,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
    },
});

transporter.verify((error, success) => {
    if (error) {
        logger.error("Email configuration error", { error: error.message });
    } else {
        logger.info("Email server is ready to send messages");
    }
});

const hashOtp = (otp) => {
    return crypto.createHash("sha256").update(otp.toString()).digest("hex");
};

const generateSecureOtp = () => {
    const otp = crypto.randomInt(100000, 999999).toString();
    const hashedOtp = crypto.createHash("sha256").update(otp).digest("hex");
    return { otp, hashedOtp };
};
const sendOtpEmail = async (email, otp, name) => {
    try {
        const displayName = (name && name.trim()) ? name : "Friend";

        if (!CONFIG.IS_PRODUCTION) {
            logger.info("📧 OTP generated (Development Mode)", {
                email,
                otp,
                displayName
            });
            return { success: true, mode: 'development' };
        }

        const mailOptions = {
            from: `"Waggetails" <${CONFIG.EMAIL_FROM}>`,
            to: email,
            subject: "Your Waggetails Verification Code",
            html: `
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <style>
            body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; line-height: 1.6; color: #333333; margin: 0; padding: 0; background-color: #FDF2E9; }
            .container { max-width: 600px; margin: 20px auto; background-color: #ffffff; border-radius: 16px; overflow: hidden; border: 1px solid #f0f0f0; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
            .header { background-color: #ffffff; padding: 30px 20px; text-align: center; border-bottom: 2px solid #FDF2E9; }
            .content { padding: 40px 30px; text-align: center; }
            .welcome-text { font-size: 18px; color: #555555; margin-bottom: 10px; }
            .main-title { font-size: 24px; font-weight: 800; color: #333333; margin-top: 0; }
            .otp-box { background-color: #FDF2E9; border-radius: 12px; padding: 25px; text-align: center; margin: 30px 0; border: 1px dashed #F69133; }
            .otp-code { font-size: 36px; font-weight: bold; letter-spacing: 10px; color: #F69133; margin: 0; }
            .expiry-text { font-size: 14px; color: #888888; margin-bottom: 25px; }
            .footer { background-color: #fcfcfc; padding: 25px; text-align: center; color: #9ca3af; font-size: 13px; border-top: 1px solid #FDF2E9; }
            .warning { color: #ef4444; font-size: 12px; margin-top: 20px; font-style: italic; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <img 
                src="https://www.waggetails.com/wp-content/uploads/2025/12/LOGO-1-2048x744.png" 
                alt="Waggetails Logo" 
                width="180" 
                style="display: block; margin: 0 auto; border:0;"
              >
            </div>
            <div class="content">
              <p class="welcome-text">Hi ${displayName}!</p>
              <h2 class="main-title">Ready to join the pack?</h2>
              <p>Use the code below to verify your email and start your journey with us.</p>
              <div class="otp-box">
                <p class="otp-code">${otp}</p>
              </div>
              <p class="expiry-text">This code expires in 10 minutes for your security.</p>
              <p>No gatekeeping, just love <span style="color:#F69133;">❤</span></p>
              <p class="warning">Never share this code with anyone. We will never ask for this code via call or text.</p>
            </div>
            <div class="footer">
              <p>Loyalty • Honesty • Playfulness</p>
              <p>© 2026 Waggetails Team. All rights reserved.</p>
            </div>
          </div>
        </body>
        </html>
      `,
            text: `Hi ${displayName}!\n\nYour Waggetails verification code is: ${otp}\n\nThis code is valid for 10 minutes.\n\nNo gatekeeping, just love.\n\nBest regards,\nThe Waggetails Team`,
        };

        const info = await transporter.sendMail(mailOptions);
        logger.info("✅ OTP email sent successfully", { email, messageId: info.messageId });
        return { success: true, messageId: info.messageId };

    } catch (error) {
        logger.error("❌ Email sending failed", { email, error: error.message });
        throw new Error("Unable to send verification email. Please try again later.");
    }
};

module.exports = {
    generateSecureOtp,
    sendOtpEmail,
    transporter,
    hashOtp,
};