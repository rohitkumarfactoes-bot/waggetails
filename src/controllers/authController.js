const User = require("../models/userModel.js");
const jwt = require("jsonwebtoken");
const { z } = require("zod");
const rateLimit = require("express-rate-limit");
const { generateSecureOtp, sendOtpEmail, hashOtp } = require("../services/emailService.js");
const crypto = require("crypto");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

//  REQUIRED ENVIRONMENT VARIABLES 
const requiredEnvVars = [
  "JWT_SECRET",
  "JWT_SIGNUP_SECRET",
  "NODE_ENV",
  "EMAIL_HOST",
  "EMAIL_PORT",
  "EMAIL_USER",
  "EMAIL_PASSWORD",
];

requiredEnvVars.forEach((varName) => {
  if (!process.env[varName]) {
    throw new Error(`❌ Missing required environment variable: ${varName}`);
  }
});

//  CONFIGURATION 
const CONFIG = {
  JWT_SECRET: process.env.JWT_SECRET,
  JWT_SIGNUP_SECRET: process.env.JWT_SIGNUP_SECRET,
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || "7d",
  IS_PRODUCTION: process.env.NODE_ENV === "production",

  MAX_OTP_ATTEMPTS: parseInt(process.env.MAX_OTP_ATTEMPTS) || 5,
  OTP_VALIDITY_MS: parseInt(process.env.OTP_VALIDITY_MS) || 10 * 60 * 1000,
  OTP_RESEND_COOLDOWN_MS: parseInt(process.env.OTP_RESEND_COOLDOWN_MS) || 60 * 1000,
  SIGNUP_SESSION_EXPIRES: parseInt(process.env.SIGNUP_SESSION_EXPIRES) || 3600,

  // JWT settings
  JWT_ISSUER: process.env.JWT_ISSUER || "waggetail-app",
  JWT_AUDIENCE: process.env.JWT_AUDIENCE || "waggetail-users",
  JWT_SIGNUP_AUDIENCE: process.env.JWT_SIGNUP_AUDIENCE || "waggetail-signup",
  COOKIE_EXPIRES_MS: 7 * 24 * 60 * 60 * 1000,
};

//  LOGGER 
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
  warn: (msg, meta = {}) => {
    console.warn(
      JSON.stringify({
        level: "warn",
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

//  SIGNUP SESSION MODEL 
const signupSessionSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, index: true },
  name: { type: String, required: true },
  username: { type: String, required: true, index: true },
  password: { type: String, required: true, select: false },
  otp: { type: String, select: false },
  otpExpires: Date,
  otpAttempts: { type: Number, default: 0 },
  isVerified: { type: Boolean, default: false },
  dob: Date,
  createdAt: { type: Date, default: Date.now, expires: CONFIG.SIGNUP_SESSION_EXPIRES },
});

signupSessionSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  try {
    this.password = await bcrypt.hash(this.password, 12);
    next();
  } catch (error) {
    next(error);
  }
});

const SignupSession = mongoose.model('SignupSession', signupSessionSchema);

//  VALIDATION SCHEMAS 
const signupSchema = z.object({
  email: z
    .string()
    .email("Invalid email address")
    .max(255, "Email cannot exceed 255 characters")
    .transform((val) => val.trim().toLowerCase()),
  name: z
    .string()
    .min(2, "Name must be at least 2 characters")
    .max(50, "Name cannot exceed 50 characters")
    .regex(/^[a-zA-Z\s]+$/, "Name can only contain letters and spaces")
    .transform((val) => val.trim()),
  username: z
    .string()
    .min(3, "Username must be at least 3 characters")
    .max(30, "Username cannot exceed 30 characters")
    .regex(
      /^[a-zA-Z0-9_]+$/,
      "Username can only contain letters, numbers, and underscores"
    )
    .transform((val) => val.trim().toLowerCase()),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(128, "Password cannot exceed 128 characters")
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])/,
      "Password must contain uppercase, lowercase, number, and special character"
    ),
});

const loginSchema = z.object({
  usernameOrEmail: z
    .string()
    .min(1, "Username or Email is required")
    .transform((val) => val.trim().toLowerCase()),
  password: z.string().min(1, "Password is required"),
});

const otpSchema = z.object({
  email: z
    .string()
    .email("Invalid email address")
    .transform((val) => val.trim().toLowerCase()),
  otp: z
    .string()
    .regex(/^\d{6}$/, "OTP must be 6 digits")
    .transform((val) => val.trim()),
});

const dobSchema = z.object({
  day: z.number().int().min(1).max(31),
  month: z.string().min(3),
  year: z.number().int().min(1900).max(new Date().getFullYear()),
});

const termsSchema = z.object({
  termsAccepted: z
    .boolean()
    .refine((val) => val === true, "You must accept the terms and conditions"),
});

//  RATE LIMITERS 
const signupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: {
    success: false,
    message: "Too many signup attempts. Please try again after 15 minutes.",
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  handler: (req, res) => {
    logger.warn("Rate limit exceeded", {
      ip: req.ip,
      path: req.path,
    });
    res.status(429).json({
      success: false,
      message: "Too many requests. Please try again later.",
    });
  },
});

const otpVerifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

const resendOtpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
});

//  UTILITY FUNCTIONS 
const secureCompare = (a, b) => {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
};

const auditLog = async (action, userId, metadata = {}) => {
  try {
    logger.info("🔍 Audit Log", {
      action,
      userId: userId?.toString(),
      timestamp: new Date().toISOString(),
      ip: metadata.ip,
      userAgent: metadata.userAgent,
      ...metadata,
    });
  } catch (error) {
    logger.error("Audit log failed", { error: error.message });
  }
};

const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch((error) => {
    logger.error("Unhandled error", {
      error: error.message,
      stack: CONFIG.IS_PRODUCTION ? undefined : error.stack,
      path: req.path,
    });

    const message = CONFIG.IS_PRODUCTION
      ? "An error occurred. Please try again."
      : error.message;

    res.status(500).json({
      success: false,
      message,
    });
  });
};

const signJwtToken = (user) => {
  return jwt.sign(
    {
      id: user._id.toString(),
      email: user.email,
      username: user.username,
      version: user.tokenVersion,
    },
    CONFIG.JWT_SECRET,
    {
      expiresIn: CONFIG.JWT_EXPIRES_IN,
      issuer: CONFIG.JWT_ISSUER,
      audience: CONFIG.JWT_AUDIENCE,
    }
  );
};

const createAndSendToken = (user, statusCode, res, message) => {
  const token = signJwtToken(user);
  const cookieOptions = {
    expires: new Date(Date.now() + CONFIG.COOKIE_EXPIRES_MS),
    httpOnly: true,
    secure: CONFIG.IS_PRODUCTION,
    sameSite: CONFIG.IS_PRODUCTION ? "strict" : "lax",
  };

  res.cookie("jwt", token, cookieOptions);

  res.status(statusCode).json({
    success: true,
    message,
    data: {
      token,
      user: user.toJSON(),
    },
  });
};

const createTemporaryToken = (sessionId, email) => {
  return jwt.sign(
    {
      sessionId: sessionId.toString(),
      email,
      signupStep: true,
    },
    CONFIG.JWT_SIGNUP_SECRET,
    {
      expiresIn: "1h",
      issuer: CONFIG.JWT_ISSUER,
      audience: CONFIG.JWT_SIGNUP_AUDIENCE,
    }
  );
};


const protectSignupStep = async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  } else if (req.cookies && req.cookies.jwt) {
    token = req.cookies.jwt;
  }

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Authorization token missing. Please restart signup process.",
    });
  }

  try {
    const decoded = jwt.verify(token, CONFIG.JWT_SIGNUP_SECRET, {
      audience: CONFIG.JWT_SIGNUP_AUDIENCE,
      issuer: CONFIG.JWT_ISSUER,
    });

    if (!decoded.signupStep) {
      return res.status(403).json({
        success: false,
        message: "Invalid token for this signup step.",
      });
    }

    req.sessionId = decoded.sessionId;
    req.sessionEmail = decoded.email;
    next();
  } catch (err) {
    logger.warn("Signup token verification failed", {
      error: err.message,
      ip: req.ip,
    });
    return res.status(401).json({
      success: false,
      message: "Invalid or expired authorization token. Please restart signup.",
    });
  }
};
exports.handleSocialAuth = async (profile, provider, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  const frontendBase = process.env.FRONTEND_URL || 'http://localhost:5173';

  try {
    const email = profile.emails?.[0]?.value || null;
    const socialId = profile.id;

    let user = await User.findOne({
      $or: [
        { [`socialLogins.${provider}`]: socialId },
        ...(email ? [{ email }] : [])
      ]
    }).select("+tokenVersion").session(session);

    if (!user) {
     
      if (!email) {
        console.warn("[SocialAuth] No email provided. Aborting and redirecting.");
        await session.abortTransaction();
        return res.redirect(
          `${frontendBase}/auth/social-complete?provider=${provider}&socialId=${encodeURIComponent(socialId)}&step=email`
        );
      }

      const cleanName = (profile.displayName || profile.username || "user")
        .replace(/\s+/g, '')
        .replace(/[^a-zA-Z0-9]/g, '')
        .toLowerCase()
        .slice(0, 10);
      
      const shortId = Date.now().toString().slice(-6);
      const finalUsername = `${cleanName}_${shortId}`.slice(0, 29);
      
      user = await User.create([{
        name: profile.displayName || profile.username || finalUsername,
        email: email,
        username: finalUsername, 
        socialLogins: { [provider]: socialId },
        isVerified: true,
        termsAccepted: false,
        tokenVersion: 0,
      }], { session });
      
      user = user[0];
    }

    if (!user.dob || !user.termsAccepted) {
      await session.commitTransaction();
      const tempToken = createTemporaryToken(user._id, user.email, user.tokenVersion || 0);
      const nextStep = !user.dob ? "dob" : "terms";
      
      return res.redirect(
        `${frontendBase}/auth/social-complete?token=${tempToken}&step=${nextStep}`
      );
    }

    if (!user.socialLogins[provider]) {
      user.socialLogins[provider] = socialId;
    }

    if (user.tokenVersion === undefined || user.tokenVersion === null) {
      user.tokenVersion = 0;
    }

    user.lastLogin = new Date();
    await user.save({ session });
    await session.commitTransaction();
    const token = signJwtToken(user);

    const cookieOptions = {
      expires: new Date(Date.now() + CONFIG.COOKIE_EXPIRES_MS),
      httpOnly: true,
      secure: CONFIG.IS_PRODUCTION,
      sameSite: CONFIG.IS_PRODUCTION ? "strict" : "lax",
      path: '/',
    };

    res.cookie("jwt", token, cookieOptions);

 
    return res.redirect(
      `${frontendBase}/auth/social-complete?success=true&token=${encodeURIComponent(token)}`
    );

  } catch (error) {
    console.error(`[SocialAuth] Critical Error: ${error.message}`);
    if (session.inAtomicalTransaction()) await session.abortTransaction();
    return res.redirect(`${frontendBase}/login?error=auth_failed`);
  } finally {
    session.endSession();
  }
};

exports.acceptTerms = [
  protectSignupStep,
  async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      const validated = termsSchema.safeParse(req.body);

      if (!validated.success) {
        await session.abortTransaction();
        return res.status(400).json({
          success: false,
          message: "Validation failed",
          errors: validated.error.issues.map((i) => ({
            field: i.path[0],
            message: i.message,
          })),
        });
      }

      let user = await User.findById(req.sessionId)
        .select('+tokenVersion')
        .session(session);
      
      if (user) {
        if (!user.dob) {
          console.warn("[AcceptTerms] DOB missing in social flow.");
          await session.abortTransaction();
          return res.status(400).json({
            success: false,
            message: "Please provide your date of birth first",
          });
        }

        if (user.tokenVersion === undefined || user.tokenVersion === null) {
          user.tokenVersion = 0;
        }

        user.termsAccepted = true;
        user.termsAcceptedAt = new Date();
        user.lastLogin = new Date();
        await user.save({ session });
        
        await session.commitTransaction();

        await auditLog("TERMS_ACCEPTED", user._id, {
          userId: user._id.toString(),
          ip: req.ip,
          userAgent: req.get("user-agent"),
        });

        createAndSendToken(user, 200, res, "Profile completed successfully");
        return;
      }
      
      const signupSession = await SignupSession.findById(req.sessionId)
        .select("+password")
        .session(session);

      if (!signupSession) {
        console.warn("[AcceptTerms] No signup session found.");
        await session.abortTransaction();
        return res.status(404).json({
          success: false,
          message: "Signup session not found. Please restart signup.",
        });
      }

      if (!signupSession.isVerified || !signupSession.dob) {
        console.warn("[AcceptTerms] Prerequisite steps (verify/dob) incomplete.");
        await session.abortTransaction();
        return res.status(400).json({
          success: false,
          message: "Prerequisite steps not completed",
        });
      }

      const existingUser = await User.findOne({
        $or: [
          { email: signupSession.email },
          { username: signupSession.username }
        ],
      }).session(session);

      if (existingUser) {
        console.warn("[AcceptTerms] Conflict: User already exists.");
        await session.abortTransaction();
        return res.status(400).json({
          success: false,
          message: "User already exists",
        });
      }

      [user] = await User.create([{
        email: signupSession.email,
        name: signupSession.name,
        username: signupSession.username,
        password: signupSession.password, 
        dob: signupSession.dob,
        isVerified: true,
        termsAccepted: true,
        termsAcceptedAt: new Date(),
        lastLogin: new Date(),
        tokenVersion: 0,
      }], { session });

      await SignupSession.deleteOne({ _id: signupSession._id }).session(session);
      await session.commitTransaction();

      await auditLog("SIGNUP_COMPLETED", user._id, {
        username: user.username,
        email: user.email,
        ip: req.ip,
        userAgent: req.get("user-agent"),
      });

      createAndSendToken(user, 200, res, "Signup completed successfully");

    } catch (error) {
      console.error(`[AcceptTerms] Catch block error: ${error.message}`);
      await session.abortTransaction();
      return res.status(500).json({
        success: false,
        message: "An error occurred. Please try again.",
      });
    } finally {
      session.endSession();
    }
  },
];

// SIGNUP ENDPOINTS
exports.signupInitiate = [
  signupLimiter,
  async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      const validated = signupSchema.safeParse(req.body);

      if (!validated.success) {
        await session.abortTransaction();
        return res.status(400).json({
          success: false,
          message: "Validation failed",
          errors: validated.error.issues.map((i) => ({
            field: i.path[0],
            message: i.message,
          })),
        });
      }

      const { email, name, username, password } = validated.data;

      // ✅ ATOMIC: Check if user already exists in User collection
      const existingUser = await User.findOne({
        $or: [{ email }, { username }],
      }).session(session);

      if (existingUser) {
        await session.abortTransaction();
        return res.status(400).json({
          success: false,
          message: existingUser.email === email
            ? "Email already registered"
            : "Username already taken",
        });
      }

      // ✅ ATOMIC: Check and delete existing signup session
      const existingSession = await SignupSession.findOne({
        $or: [{ email }, { username }],
      }).session(session);

      if (existingSession) {
        await SignupSession.deleteOne({ _id: existingSession._id }).session(session);
      }

      const { otp, hashedOtp } = generateSecureOtp();

      // ✅ ATOMIC: Create temporary signup session
      const [signupSession] = await SignupSession.create([{
        email,
        name,
        username,
        password, // Will be hashed by pre-save hook
        otp: hashedOtp,
        otpExpires: Date.now() + CONFIG.OTP_VALIDITY_MS,
        otpAttempts: 0,
        isVerified: false,
      }], { session });

      // ✅ Commit transaction BEFORE sending email (email is not critical)
      await session.commitTransaction();

      // Send email after transaction is committed
      await sendOtpEmail(email, otp, name);

      await auditLog("SIGNUP_INITIATED", null, {
        email,
        username,
        sessionId: signupSession._id.toString(),
        ip: req.ip,
        userAgent: req.get("user-agent"),
      });

      return res.status(200).json({
        success: true,
        message: "OTP sent successfully to your email address",
        data: {
          expiresIn: CONFIG.OTP_VALIDITY_MS / 1000,
          email,
        },
      });

    } catch (error) {
      await session.abortTransaction();
      logger.error("Signup initiate error", { error: error.message });
      return res.status(500).json({
        success: false,
        message: "An error occurred during signup. Please try again.",
      });
    } finally {
      session.endSession();
    }
  },
];

// STEP 2: Verify OTP
exports.verifyOtp = [
  otpVerifyLimiter,
  async (req, res) => {
    try {
      const validated = otpSchema.safeParse(req.body);

      if (!validated.success) {
        return res.status(400).json({
          success: false,
          message: "Validation failed",
          errors: validated.error.issues.map((i) => ({
            field: i.path[0],
            message: i.message,
          })),
        });
      }

      const { email, otp } = validated.data;

      const signupSession = await SignupSession.findOne({ email }).select("+otp +password");

      if (!signupSession) {
        return res.status(404).json({
          success: false,
          message: "Signup session not found. Please restart signup.",
        });
      }

      if (signupSession.isVerified) {
        return res.status(400).json({
          success: false,
          message: "Email already verified",
        });
      }

      if (signupSession.otpAttempts >= CONFIG.MAX_OTP_ATTEMPTS) {
        await auditLog("OTP_MAX_ATTEMPTS_EXCEEDED", null, {
          email,
          sessionId: signupSession._id.toString(),
          attempts: signupSession.otpAttempts,
          ip: req.ip,
        });
        return res.status(429).json({
          success: false,
          message: "Maximum OTP attempts exceeded. Please request a new OTP.",
        });
      }

      if (!signupSession.otpExpires || signupSession.otpExpires < Date.now()) {
        await auditLog("OTP_EXPIRED", null, {
          email,
          sessionId: signupSession._id.toString(),
          ip: req.ip
        });
        return res.status(400).json({
          success: false,
          message: "OTP has expired. Please request a new one.",
        });
      }

      const hashedInputOtp = hashOtp(otp.toString());

      if (!signupSession.otp || !secureCompare(signupSession.otp, hashedInputOtp)) {
        signupSession.otpAttempts += 1;
        await signupSession.save();

        await auditLog("OTP_INVALID", null, {
          email,
          sessionId: signupSession._id.toString(),
          attempts: signupSession.otpAttempts,
          ip: req.ip,
        });

        return res.status(400).json({
          success: false,
          message: "Invalid OTP",
          attemptsRemaining: Math.max(0, CONFIG.MAX_OTP_ATTEMPTS - signupSession.otpAttempts),
        });
      }

      signupSession.isVerified = true;
      signupSession.otpAttempts = 0;
      signupSession.otp = undefined;
      signupSession.otpExpires = undefined;
      await signupSession.save();

      const tempToken = createTemporaryToken(signupSession._id, signupSession.email);

      await auditLog("OTP_VERIFIED", null, {
        email,
        sessionId: signupSession._id.toString(),
        ip: req.ip
      });

      return res.status(200).json({
        success: true,
        message: "Email verified successfully",
        data: {
          token: tempToken,
        },
      });

    } catch (error) {
      logger.error("OTP verification error", { error: error.message });
      return res.status(500).json({
        success: false,
        message: "An error occurred. Please try again.",
      });
    }
  },
];

// STEP 3: Save DOB
exports.saveDob = [
  protectSignupStep,
  async (req, res) => {
    try {
      const validated = dobSchema.safeParse(req.body);

      if (!validated.success) {
        return res.status(400).json({
          success: false,
          message: "Validation failed",
          errors: validated.error.issues.map((i) => ({
            field: i.path[0],
            message: i.message,
          })),
        });
      }

      const { day, month, year } = validated.data;

      const months = [
        "January", "February", "March", "April", "May", "June",
        "July", "August", "September", "October", "November", "December",
      ];

      const monthIndex = months.findIndex(
        (m) => m.toLowerCase() === month.toLowerCase()
      );

      if (monthIndex === -1) {
        return res.status(400).json({
          success: false,
          message: "Invalid month name",
        });
      }

      const dob = new Date(year, monthIndex, day);

      if (
        isNaN(dob.getTime()) ||
        dob.getMonth() !== monthIndex ||
        dob.getFullYear() !== year
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid date format or date does not exist.",
        });
      }

      // Try to find User (from social login) first
      let user = await User.findById(req.sessionId);

      if (user) {
        // Social login flow - update User directly
        user.dob = dob;
        await user.save();

        await auditLog("DOB_SAVED", user._id, {
          userId: user._id.toString(),
          dob: dob.toISOString().split("T")[0],
          ip: req.ip,
        });

        return res.status(200).json({
          success: true,
          message: "Date of Birth saved successfully",
          data: { dob: user.dob },
        });
      }

      // Try to find SignupSession (from regular signup)
      const signupSession = await SignupSession.findById(req.sessionId);

      if (!signupSession) {
        return res.status(404).json({
          success: false,
          message: "Signup session not found. Please restart signup.",
        });
      }

      if (!signupSession.isVerified) {
        return res.status(400).json({
          success: false,
          message: "Please verify your email first.",
        });
      }

      signupSession.dob = dob;
      await signupSession.save();

      await auditLog("DOB_SAVED", null, {
        sessionId: signupSession._id.toString(),
        dob: dob.toISOString().split("T")[0],
        ip: req.ip,
      });

      return res.status(200).json({
        success: true,
        message: "Date of Birth saved successfully",
        data: { dob: signupSession.dob },
      });

    } catch (error) {
      logger.error("DOB save error", { error: error.message });
      return res.status(500).json({
        success: false,
        message: "An error occurred. Please try again.",
      });
    }
  },
];

// STEP 4: Accept Terms (Create ACTUAL User in DB)
exports.acceptTerms = [
  protectSignupStep,
  async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      const validated = termsSchema.safeParse(req.body);

      if (!validated.success) {
        await session.abortTransaction();
        return res.status(400).json({
          success: false,
          message: "Validation failed",
          errors: validated.error.issues.map((i) => ({
            field: i.path[0],
            message: i.message,
          })),
        });
      }

      // Try to find User (from social login) first
      let user = await User.findById(req.sessionId).select("+tokenVersion").session(session);

      if (user) {
        // Social login flow - update User directly and login
        if (!user.dob) {
          await session.abortTransaction();
          return res.status(400).json({
            success: false,
            message: "Please provide your date of birth first",
          });
        }

        user.termsAccepted = true;
        user.termsAcceptedAt = new Date();
        user.lastLogin = new Date();
        await user.save({ session });

        await session.commitTransaction();

        await auditLog("TERMS_ACCEPTED", user._id, {
          userId: user._id.toString(),
          ip: req.ip,
          userAgent: req.get("user-agent"),
        });

        // Social login is complete, send token and login
        createAndSendToken(user, 200, res, "Profile completed successfully");
        return;
      }

      // Try to find SignupSession (from regular signup)
      const signupSession = await SignupSession.findById(req.sessionId)
        .select("+password")
        .session(session);

      if (!signupSession) {
        await session.abortTransaction();
        return res.status(404).json({
          success: false,
          message: "Signup session not found. Please restart signup.",
        });
      }

      if (!signupSession.isVerified) {
        await session.abortTransaction();
        return res.status(400).json({
          success: false,
          message: "Please verify your email address first",
        });
      }

      if (!signupSession.dob) {
        await session.abortTransaction();
        return res.status(400).json({
          success: false,
          message: "Please provide your date of birth first",
        });
      }

      // ✅ ATOMIC: Double-check if user exists (prevent race conditions)
      const existingUser = await User.findOne({
        $or: [
          { email: signupSession.email },
          { username: signupSession.username }
        ],
      }).session(session);

      if (existingUser) {
        await session.abortTransaction();
        return res.status(400).json({
          success: false,
          message: "User already exists",
        });
      }


      [user] = await User.create([{
        email: signupSession.email,
        name: signupSession.name,
        username: signupSession.username,
        password: signupSession.password,
        dob: signupSession.dob,
        isVerified: true,
        termsAccepted: true,
        termsAcceptedAt: new Date(),
        lastLogin: new Date(),
        tokenVersion: 0,
      }], { session });

      await SignupSession.deleteOne({ _id: signupSession._id }).session(session);

      await session.commitTransaction();

      await auditLog("SIGNUP_COMPLETED", user._id, {
        username: user.username,
        email: user.email,
        ip: req.ip,
        userAgent: req.get("user-agent"),
      });

      createAndSendToken(user, 200, res, "Signup completed successfully");

    } catch (error) {
      await session.abortTransaction();
      logger.error("Accept terms error", { error: error.message });
      return res.status(500).json({
        success: false,
        message: "An error occurred. Please try again.",
      });
    } finally {
      session.endSession();
    }
  },
];

// Resend OTP
exports.resendOtp = [
  resendOtpLimiter,
  async (req, res) => {
    try {
      const { email } = req.body;

      const emailValidation = z.string().email();
      const result = emailValidation.safeParse(email);

      if (!result.success) {
        return res.status(400).json({
          success: false,
          message: "Invalid email address",
        });
      }

      const normalizedEmail = email.trim().toLowerCase();

      const signupSession = await SignupSession.findOne({ email: normalizedEmail });

      if (!signupSession) {
        return res.status(404).json({
          success: false,
          message: "Signup session not found. Please restart signup.",
        });
      }

      if (signupSession.isVerified) {
        return res.status(400).json({
          success: false,
          message: "Email already verified",
        });
      }

      if (signupSession.otpExpires) {
        const timeSinceLastOtp = Date.now() - (signupSession.otpExpires - CONFIG.OTP_VALIDITY_MS);
        const cooldownRemaining = CONFIG.OTP_RESEND_COOLDOWN_MS - timeSinceLastOtp;

        if (cooldownRemaining > 0) {
          await auditLog("OTP_RESEND_COOLDOWN", null, {
            email: normalizedEmail,
            sessionId: signupSession._id.toString(),
            cooldownRemaining,
            ip: req.ip,
          });

          return res.status(429).json({
            success: false,
            message: `Please wait ${Math.ceil(cooldownRemaining / 1000)} seconds before requesting a new OTP`,
            retryAfter: Math.ceil(cooldownRemaining / 1000),
          });
        }
      }

      const { otp, hashedOtp } = generateSecureOtp();

      signupSession.otp = hashedOtp;
      signupSession.otpExpires = Date.now() + CONFIG.OTP_VALIDITY_MS;
      signupSession.otpAttempts = 0;
      await signupSession.save();

      await sendOtpEmail(normalizedEmail, otp, signupSession.name);

      await auditLog("OTP_RESENT", null, {
        email: normalizedEmail,
        sessionId: signupSession._id.toString(),
        ip: req.ip,
      });

      return res.status(200).json({
        success: true,
        message: "OTP resent successfully",
        data: {
          expiresIn: CONFIG.OTP_VALIDITY_MS / 1000,
        },
      });

    } catch (error) {
      logger.error("Resend OTP error", { error: error.message });
      return res.status(500).json({
        success: false,
        message: "An error occurred. Please try again.",
      });
    }
  },
];

//  LOGIN & LOGOUT 

exports.login = [
  loginLimiter,
  asyncHandler(async (req, res) => {
    const validated = loginSchema.safeParse(req.body);

    if (!validated.success) {
      return res.status(400).json({
        success: false,
        message: "Validation failed",
        errors: validated.error.issues.map((i) => ({
          field: i.path[0],
          message: i.message,
        })),
      });
    }

    const { usernameOrEmail, password } = validated.data;
    const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(usernameOrEmail);
    const query = isEmail ? { email: usernameOrEmail } : { username: usernameOrEmail };

    const user = await User.findOne(query).select("+password +tokenVersion");

    if (!user) {
      // Perform a dummy hash comparison to prevent timing attacks
      await User.dummyCompare?.() || false;
      // Continue with error handling below
    }

    const isValidPassword = user ? await user.comparePassword(password) : false;

    if (!user || !isValidPassword) {
      await auditLog("LOGIN_FAILED", user?._id, {
        identifier: usernameOrEmail,
        reason: !user ? "User not found" : "Invalid password",
        ip: req.ip,
      });
      // Provide more helpful error messages while maintaining security
      if (!user) {
        return res.status(401).json({
          success: false,
          message: "No account found with this username or email. Please check and try again, or sign up.",
        });
      } else {
        return res.status(401).json({
          success: false,
          message: "Password is incorrect. Please try again.",
        });
      }
    }

    if (user.accountStatus !== "active") {
      await auditLog("LOGIN_BLOCKED_STATUS", user._id, { status: user.accountStatus, ip: req.ip });
      return res.status(403).json({
        success: false,
        message: `Your account is ${user.accountStatus}. Please contact support.`,
      });
    }

    if (!user.isVerified) {
      await auditLog("LOGIN_BLOCKED_UNVERIFIED", user._id, { ip: req.ip });
      return res.status(403).json({
        success: false,
        message: "Email is not verified.",
        requiresVerification: true,
      });
    }

    if (!user.termsAccepted) {
      await auditLog("LOGIN_BLOCKED_TERMS", user._id, { ip: req.ip });
      const tempToken = createTemporaryToken(user._id, user.email);
      return res.status(403).json({
        success: false,
        message: "Please accept the terms and conditions.",
        data: { token: tempToken, nextStep: "/accept-terms" },
      });
    }

    await User.updateOne(
      { _id: user._id },
      { $set: { lastLogin: new Date() } }
    );

    await auditLog("LOGIN_SUCCESS", user._id, {
      username: user.username,
      ip: req.ip,
      userAgent: req.get("user-agent"),
    });

    createAndSendToken(user, 200, res, "Logged in successfully");
  }),
];
exports.logout = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id).select("+tokenVersion");

  if (!user) {
    return res.status(404).json({
      success: false,
      message: "User not found",
    });
  }

  user.tokenVersion = (user.tokenVersion || 0) + 1;
  await user.save();

  await auditLog("LOGOUT_SUCCESS", user._id, {
    username: user.username,
    ip: req.ip,
    userAgent: req.get("user-agent"),
  });

  res.cookie("jwt", "", {
    httpOnly: true,
    expires: new Date(0),
    secure: CONFIG.IS_PRODUCTION,
    sameSite: CONFIG.IS_PRODUCTION ? "strict" : "lax",
  });

  res.status(200).json({
    success: true,
    message: "Logged out successfully",
  });
});

module.exports = exports;