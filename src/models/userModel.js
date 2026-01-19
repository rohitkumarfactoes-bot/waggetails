const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const BCRYPT_SALT_ROUNDS = 10;
const ACCOUNT_STATUSES = ["active", "suspended", "deleted", "pending"];

const userSchema = new mongoose.Schema(
    {
        name: {
            type: String,
            required: true,
            trim: true,
            minlength: 2,
            maxlength: 50,
        },
        username: {
            type: String,
            required: true,
            unique: true,
            trim: true,
            lowercase: true,
            minlength: 3,
            maxlength: 30,
            match: /^[a-zA-Z0-9_]+$/,
        },
        email: {
            type: String,
            lowercase: true,
            required: true,
            unique: true,
            trim: true,
            match: /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
        },
        mobileNumber: {
            type: String,
            unique: true,
            sparse: true,
            trim: true,
            match: /^[6-9]\d{9}$/,
        },
        dob: { type: Date },
        password: {
            type: String,
            required: function () {
                return (
                    !this.socialLogins || 
                    (!this.socialLogins.google && !this.socialLogins.instagram && !this.socialLogins.tiktok)
                );
            },
            minlength: 8,
            select: false,
        },
        socialLogins: {
            google: { type: String, index: { unique: true, sparse: true } },
            instagram: { type: String, index: { unique: true, sparse: true } }, 
            tiktok: { type: String, index: { unique: true, sparse: true } },   
        },
        profilePhoto: { 
            type: String, 
            default: "https://waggetail.s3.ap-south-1.amazonaws.com/defaults/db.png" 
        },
        pronouns: {
            type: String,
            trim: true,
            maxlength: 50,
            default: "He",
        },
        bio: { type: String, maxlength: 500, trim: true },
        isAdmin: { type: Boolean, default: false },
        isVerified: { type: Boolean, default: false, index: true },
        termsAccepted: { type: Boolean, default: false, required: true },
        termsAcceptedAt: { type: Date },
        otp: { type: String, select: false },
        otpExpires: { type: Date, select: false },
        otpAttempts: { type: Number, default: 0, select: false },
        tokenVersion: { type: Number, default: 0, select: false },
        isPrivate: { type: Boolean, default: false },
        lastLogin: { type: Date, default: Date.now },
        accountStatus: {
            type: String,
            enum: ACCOUNT_STATUSES,
            default: "active",
            index: true,
        },
    },
    {
        timestamps: true,
        versionKey: false,
        toJSON: { virtuals: true },
        toObject: { virtuals: true },
    }
);

userSchema.index({ email: 1, accountStatus: 1 });
userSchema.index({ username: 1, accountStatus: 1 });

userSchema.virtual("posts", { ref: "Post", localField: "_id", foreignField: "owner", justOne: false });
userSchema.virtual("followers", { ref: "Follow", localField: "_id", foreignField: "following", justOne: false });
userSchema.virtual("following", { ref: "Follow", localField: "_id", foreignField: "follower", justOne: false });


userSchema.methods.comparePassword = async function (candidatePassword) {
    if (!this.password) return false;
    return await bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.invalidateTokens = async function () {
    this.tokenVersion += 1;
    return await this.save();
};

userSchema.methods.toJSON = function () {
    const user = this.toObject();
    delete user.password;
    delete user.otp;
    delete user.otpExpires;
    delete user.otpAttempts;
    delete user.tokenVersion;
    if (user.socialLogins) {
        delete user.socialLogins.google;
        delete user.socialLogins.instagram;
        delete user.socialLogins.tiktok;
    }
    return user;
};

module.exports = mongoose.model("User", userSchema);