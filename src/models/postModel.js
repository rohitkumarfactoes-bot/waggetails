const mongoose = require("mongoose");

const postSchema = new mongoose.Schema(
  {
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },

    mediaUrl: {
      type: String,
      required: true,
      validate: {
        validator: v => /^https?:\/\/.+/.test(v),
        message: 'Invalid URL format'
      }
    },

    mediaType: {
      type: String,
      enum: ["image", "video"],
      required: true,
    },

    caption: {
      type: String,
      maxlength: 2200,
      trim: true,
    },

    hashtags: [{
      type: String,
      trim: true,
      lowercase: true,
    }],

    likes: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: "User"
    }],

    commentsCount: {
      type: Number,
      default: 0,
    },

    sharesCount: {
      type: Number,
      default: 0,
    },

    location: {
      type: String,
      trim: true,
      maxlength: 100
    },

    isDeleted: { type: Boolean, default: false, select: false },
    isArchived: { type: Boolean, default: false, select: false },
  },
  {
    timestamps: true,
    versionKey: false,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

postSchema.virtual('likesCount').get(function () {
  return this.likes ? this.likes.length : 0;
});

postSchema.index({ owner: 1, createdAt: -1 });
postSchema.index({ hashtags: 1, createdAt: -1 });
postSchema.index({ createdAt: -1 });

postSchema.methods.toJSON = function () {
  const post = this.toObject();


  return post;
};

module.exports = mongoose.model("Post", postSchema);