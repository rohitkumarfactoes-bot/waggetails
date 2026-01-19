require("dotenv").config();

// Validate required environment variables
const requiredEnvVars = [
  "MONGO_URI",
  "JWT_SECRET",
  "NODE_ENV",
  "AWS_REGION",
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_S3_BUCKET_NAME",
];

requiredEnvVars.forEach((varName) => {
  if (!process.env[varName]) {
    throw new Error(`❌ Missing required environment variable: ${varName}`);
  }
});

const CONFIG = {
  // Server
  NODE_ENV: process.env.NODE_ENV || "development",
  PORT: process.env.PORT || 5000,
  IS_PRODUCTION: process.env.NODE_ENV === "production",

  // Database
  MONGO_URI: process.env.MONGO_URI,

  // JWT
  JWT_SECRET: process.env.JWT_SECRET,
  REFRESH_TOKEN_SECRET: process.env.REFRESH_TOKEN_SECRET,
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || "15m",
  JWT_ISSUER: process.env.JWT_ISSUER || "waggetail-app",
  JWT_AUDIENCE: process.env.JWT_AUDIENCE || "waggetail-users",
  COOKIE_EXPIRES_MS: 7 * 24 * 60 * 60 * 1000,

  // OTP
  MAX_OTP_ATTEMPTS: 5,
  OTP_VALIDITY_MS: 10 * 60 * 1000,
  OTP_RESEND_COOLDOWN_MS: 60 * 1000,
  OTP_LENGTH: 6,

  // AWS
  AWS_REGION: process.env.AWS_REGION,
  AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
  AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
  AWS_S3_BUCKET_NAME: process.env.AWS_S3_BUCKET_NAME,
  AWS_S3_BUCKET_REGION:
    process.env.AWS_S3_BUCKET_REGION || process.env.AWS_REGION,
  s3: {
    bucket: process.env.AWS_S3_BUCKET_NAME,
    region: process.env.AWS_S3_BUCKET_REGION || process.env.AWS_REGION,
    accessKey: process.env.AWS_ACCESS_KEY_ID,
    secretKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
  // File Upload
  MAX_FILE_SIZE: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024,
  MAX_IMAGE_SIZE: parseInt(process.env.MAX_IMAGE_SIZE) || 5 * 1024 * 1024,
  MAX_VIDEO_SIZE: parseInt(process.env.MAX_VIDEO_SIZE) || 100 * 1024 * 1024,
  ALLOWED_IMAGE_TYPES: ["image/jpeg", "image/png", "image/webp", "image/heic"],
  ALLOWED_VIDEO_TYPES: ["video/mp4", "video/quicktime", "video/x-msvideo"],

  // CORS
  ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS?.split(",") || [
    "http://localhost:3000",
  ],

  // Pagination
  MAX_POSTS_PER_PAGE: 20,
  MAX_CAPTION_LENGTH: 2200,
  MAX_HASHTAGS: 30,
};

module.exports = CONFIG;
