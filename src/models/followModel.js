const mongoose = require("mongoose");

const followSchema = new mongoose.Schema(
    {
        follower: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true,
            index: true,
        },
        following: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true,
            index: true,
        },
        status: {
            type: String,
            enum: ["pending", "accepted"],
            default: "accepted",
            index: true
        }
    },
    {
        timestamps: true,
        versionKey: false,
    }
);

followSchema.index({ follower: 1, following: 1 }, { unique: true });

followSchema.pre('save', function (next) {
    if (this.follower.equals(this.following)) {
        return next(new Error("Users cannot follow themselves."));
    }
    next();
});

module.exports = mongoose.model("Follow", followSchema);