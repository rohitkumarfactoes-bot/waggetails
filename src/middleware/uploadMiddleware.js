const multer = require("multer");
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
const CONFIG = require("../config/config");

const s3Client = new S3Client({
    credentials: {
        accessKeyId: CONFIG.s3.accessKey,
        secretAccessKey: CONFIG.s3.secretKey,
    },
    region: CONFIG.s3.region,
});

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024 },
});

exports.uploadMiddleware = (req, res, next) => {
    upload.single("file")(req, res, async (err) => {
        if (err) {
            return res.status(400).json({ message: `File upload failed: ${err.message}` });
        }

        const file = req.file;

        if (!file) {
            return next();
        }

        try {
            const safeFileName = file.originalname.replace(/[^a-z0-9.]/gi, '_').toLowerCase();
            const key = `posts/${Date.now()}-${safeFileName}`;
            const mediaUrl = `https://${CONFIG.s3.bucket}.s3.${CONFIG.s3.region}.amazonaws.com/${key}`;
            const params = {
                Bucket: CONFIG.s3.bucket,
                Key: key,
                Body: file.buffer,
                ContentType: file.mimetype,
            };

            await s3Client.send(new PutObjectCommand(params));

            req.file.location = mediaUrl;
            req.file.key = key;
            next();
        } catch (s3Error) {
            console.error("Error uploading file to S3:", s3Error);
            return res.status(500).json({ message: "Error uploading file to storage" });
        }
    });
};
