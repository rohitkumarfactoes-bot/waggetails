const { PutObjectCommand } = require("@aws-sdk/client-s3");
const { s3Client } = require("../services/aws");
const path = require("path");

async function uploadToS3(file) {
  if (!file) throw new Error("File is required");

  const fileExt = path.extname(file.originalname);
  const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1e9)}${fileExt}`;

  const params = {
    Bucket: process.env.AWS_S3_BUCKET_NAME,
    Key: `posts/${uniqueName}`,
    Body: file.buffer,
    ContentType: file.mimetype,
    ACL: "public-read",
  };

  await s3Client.send(new PutObjectCommand(params));

  return `https://${process.env.AWS_S3_BUCKET_NAME}.s3.${process.env.AWS_S3_BUCKET_REGION}.amazonaws.com/posts/${uniqueName}`;
}

module.exports = { uploadToS3 };
