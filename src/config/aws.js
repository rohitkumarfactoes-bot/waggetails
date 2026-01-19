const { S3Client } = require("@aws-sdk/client-s3");
const { SNSClient } = require("@aws-sdk/client-sns");
const CONFIG = require("./config");

// S3 Client Configuration
const s3Client = new S3Client({
  region: CONFIG.AWS_S3_BUCKET_REGION,
  credentials: {
    accessKeyId: CONFIG.AWS_ACCESS_KEY_ID,
    secretAccessKey: CONFIG.AWS_SECRET_ACCESS_KEY,
  },
  maxAttempts: 3,
});

// SNS Client Configuration
const snsClient = new SNSClient({
  region: CONFIG.AWS_REGION,
  credentials: {
    accessKeyId: CONFIG.AWS_ACCESS_KEY_ID,
    secretAccessKey: CONFIG.AWS_SECRET_ACCESS_KEY,
  },
  maxAttempts: 3,
});

module.exports = {
  s3Client,
  snsClient,
};