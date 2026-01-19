const z = require('zod');
const { postService } = require("../services/postService");
const { uploadMiddleware } = require("../middleware/uploadMiddleware");

const createPostSchema = z.object({
    caption: z.string().max(2000, "Caption too long").optional(),
    location: z.string().max(100, "Location too long").optional(),
    hashtags: z.string().optional(),
    collab: z.string().optional(),
});

const updatePostDescriptionSchema = z.object({
    caption: z.string().max(2000, "Caption too long").optional(),
    location: z.string().max(100, "Location too long").optional(),
    hashtags: z.string().optional(),
}).partial();

const deletePostSchema = z.object({
    postId: z.string().min(1, "Post ID is required"),
});

function getFileType(mime) {
    if (!mime) return "unknown";
    if (mime.startsWith("image/")) return "image";
    if (mime.startsWith("video/")) return "video";
    return "unknown";
}

exports.uploadMiddleware = uploadMiddleware;

exports.createPost = async (req, res) => {
    try {
        const userId = req.user?.id;

        const parsed = createPostSchema.safeParse({
            caption: req.body.caption,
            location: req.body.location,
            hashtags: req.body.hashtags,
            collab: req.body.collab,
        });

        if (!parsed.success) {
            return res.status(422).json({
                message: "Validation failed",
                errors: parsed.error.errors,
            });
        }

        const file = req.file;

        if (!file) {
            return res.status(400).json({ message: "Media file is required" });
        }

        const mediaUrl = file.location;
        const mediaType = getFileType(file.mimetype);

        if (mediaType === "unknown") {
            return res.status(400).json({ message: "Unsupported media type" });
        }

        const tagsString = parsed.data.hashtags || "";
        const hashtagsArray = tagsString
            .split(',')
            .map(tag => tag.trim())
            .filter(tag => tag.length > 0);

        const post = await postService.createPost({
            userId,
            caption: parsed.data.caption || "",
            location: parsed.data.location || "",
            hashtags: hashtagsArray,
            mediaUrl,
            mediaType,
        });

        res.status(201).json({ message: "Post created successfully", post });
    } catch (error) {
        console.error("Error creating post:", error);
        res.status(500).json({ message: "An unexpected error occurred. Please try again later." });
    }
};

exports.getFeed = async (req, res) => {
    try {
        const userId = req.user?.id;
        const feed = await postService.getFeed(userId);
        res.status(200).json({ message: "Feed fetched successfully", feed });
    } catch (error) {
        res.status(500).json({ message: "Error fetching feed", error: "An unexpected error occurred" });
    }
};

exports.getPostsByHashtag = async (req, res) => {
    try {
        const tag = req.params.tag;
        const posts = await postService.getPostsByHashtag(tag);
        res.status(200).json({ message: `Posts for hashtag #${tag} fetched successfully`, posts });
    } catch (error) {
        res.status(500).json({ message: "Error fetching posts by hashtag", error: "An unexpected error occurred" });
    }
};

exports.getPostById = async (req, res) => {
    try {
        const postId = req.params.id;
        const post = await postService.getSinglePost(postId);

        if (!post) {
            return res.status(404).json({ message: "Post not found" });
        }

        res.status(200).json({ message: "Post fetched successfully", post });
    } catch (error) {
        res.status(500).json({ message: "Error fetching post", error: "An unexpected error occurred" });
    }
};

exports.getUserPosts = async (req, res) => {
    try {
        const username = req.params.username;
        const posts = await postService.getUserPostsByUsername(username);
        res.status(200).json({ message: "User posts fetched successfully", posts });
    } catch (error) {
        res.status(500).json({ message: "Error fetching user posts", error: "An unexpected error occurred" });
    }
};

exports.updatePost = async (req, res) => {
    try {
        const userId = req.user?.id;
        const postId = req.params.id;

        const parsed = updatePostDescriptionSchema.safeParse({
            caption: req.body.caption,
            location: req.body.location,
            hashtags: req.body.hashtags,
        });

        if (!parsed.success) {
            return res.status(422).json({
                message: "Validation failed",
                errors: parsed.error.errors,
            });
        }

        const updated = await postService.updatePost(postId, userId, parsed.data);

        if (!updated) {
            return res.status(404).json({ message: "Post not found or not authorized" });
        }

        res.status(200).json({ message: "Post updated successfully", updated });
    } catch (error) {
        res.status(500).json({ message: "Error updating post", error: "An unexpected error occurred" });
    }
};

exports.deletePost = async (req, res) => {
    try {
        const userId = req.user?.id;

        const parsed = deletePostSchema.safeParse({
            postId: req.params.id,
        });

        if (!parsed.success) {
            return res.status(422).json({
                message: "Validation failed",
                errors: parsed.error.errors,
            });
        }

        const deleted = await postService.deletePost(parsed.data.postId, userId);

        if (!deleted) {
            return res.status(404).json({ message: "Post not found or not authorized" });
        }

        res.status(200).json({ message: "Post deleted successfully" });
    } catch (error) {
        res.status(500).json({ message: "Error deleting post", error: "An unexpected error occurred" });
    }
};

exports.toggleLike = async (req, res) => {
    try {
        const userId = req.user.id;
        const postId = req.params.id;

        const result = await postService.toggleLike(postId, userId);

        res.status(200).json({
            success: true,
            postId,
            liked: result.liked,
            likesCount: result.likesCount,
            message: result.message,
        });
    } catch (error) {
        console.error("Toggle like error:", error);
        res.status(500).json({
            success: false,
            message: "Error processing like",
        });
    }
};
exports.toggleArchive = async (req, res) => {
    try {
        const userId = req.user.id;
        const postId = req.params.id;

        const result = await postService.toggleArchive(postId, userId);

        res.status(200).json({ message: result.message, archived: result.archived });
    } catch (error) {
        res.status(500).json({ message: "Error processing archive status", error: "An unexpected error occurred" });
    }
};

exports.getTimelineFeed = async (req, res) => {
    try {
        const userId = req.user.id;
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 12;

        const result = await postService.getTimelineFeed(userId, page, limit);

        res.status(200).json({
            success: true,
            data: result.posts,
            pagination: {
                currentPage: page,
                hasNextPage: result.hasNextPage,
                totalPosts: result.totalCount
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Error fetching timeline feed"
        });
    }
};

exports.getExploreFeed = async (req, res) => {
    try {
        const userId = req.user.id;
        const page = Math.max(1, parseInt(req.query.page) || 1);
        const limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 20));
        const excludeFollowing = req.query.excludeFollowing === 'true'; // Convert string to boolean

        const result = await postService.getExploreFeed(userId, page, limit, excludeFollowing);

        return res.status(200).json({
            success: true,
            message: "Explore feed fetched successfully",
            data: result.posts,
            pagination: {
                currentPage: result.currentPage,
                totalPages: result.totalPages,
                totalPosts: result.totalCount,
                hasNextPage: result.hasNextPage,
                hasPrevPage: result.hasPrevPage,
                limit
            }
        });
    } catch (error) {
        console.error("Explore Feed Controller Error:", error);
        return res.status(500).json({
            success: false,
            message: error.message || "Error fetching explore feed",
            data: null
        });
    }
};
// Get trending explore feed - popular posts sorted by engagement

exports.getTrendingExploreFeed = async (req, res) => {
    try {
        const userId = req.user.id;
        const page = Math.max(1, parseInt(req.query.page) || 1);
        const limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 20));

        const result = await postService.getTrendingExploreFeed(userId, page, limit);

        return res.status(200).json({
            success: true,
            message: "Trending explore feed fetched successfully",
            data: result.posts,
            pagination: {
                currentPage: result.currentPage,
                totalPages: result.totalPages,
                totalPosts: result.totalCount,
                hasNextPage: result.hasNextPage,
                hasPrevPage: result.hasPrevPage,
                limit
            }
        });
    } catch (error) {
        console.error("Trending Explore Controller Error:", error);
        return res.status(500).json({
            success: false,
            message: error.message || "Error fetching trending explore feed",
            data: null
        });
    }
};