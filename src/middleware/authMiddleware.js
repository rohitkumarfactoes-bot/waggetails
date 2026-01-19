const jwt = require("jsonwebtoken");
const User = require("../models/userModel");
const CONFIG = {
    JWT_SECRET: process.env.JWT_SECRET,
};

const asyncHandler = (fn) => (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);

const authProtect = (allowedRoles = null) =>
    asyncHandler(async (req, res, next) => {
        let token;

        if (req.headers.authorization?.startsWith("Bearer")) {
            token = req.headers.authorization.split(" ")[1];
        } else if (req.cookies && req.cookies.jwt) {
            token = req.cookies.jwt;
           
        }

        if (!token) {
            console.warn("AUTH FAILURE: No token found in headers or cookies.");
            return res.status(401).json({
                success: false,
                message: "Unauthorized: Please log in.",
            });
        }

        let decoded;
        try {
            decoded = jwt.verify(token, CONFIG.JWT_SECRET);
            
        } catch (error) {
            console.error("JWT VERIFICATION ERROR:", error.message);
            return res.status(401).json({
                success: false,
                message: "Unauthorized: Invalid or expired token.",
            });
        }

        const user = await User.findById(decoded.id).select(
            "+tokenVersion accountStatus role"
        );

        if (!user) {
            console.warn(`AUTH FAILURE: User ${decoded.id} not found in database.`);
            return res.status(401).json({
                success: false,
                message: "Unauthorized: User does not exist.",
            });
        }

        if (user.accountStatus !== "active") {
            return res.status(403).json({
                success: false,
                message: `Account is ${user.accountStatus}.`,
            });
        }

        if (user.tokenVersion !== decoded.version) {
            console.warn(`AUTH FAILURE: Token version mismatch. DB: ${user.tokenVersion}, JWT: ${decoded.version}`);
            return res.status(401).json({
                success: false,
                message: "Session expired. Please log in again.",
            });
        }

        if (allowedRoles && !allowedRoles.includes(user.role)) {
            console.warn(`AUTH FAILURE: Insufficient permissions. Role: ${user.role}, Allowed: [${allowedRoles}]`);
            return res.status(403).json({
                success: false,
                message: "Forbidden: Insufficient permission.",
            });
        }
        

        if (req.headers.authorization?.startsWith("Bearer")) {
            const cookieOptions = {
                expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
                path: '/',
            };
            res.cookie("jwt", token, cookieOptions);
        }
        
        req.user = user;
        next();
    });

module.exports = { authProtect };