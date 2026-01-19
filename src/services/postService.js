const Post = require('../models/postModel');
const User = require('../models/userModel');
const Follow = require('../models/followModel');
const mongoose = require('mongoose');

const postService = {
    async createPost(postData) {


        try {
            const newPost = new Post({
                ...postData,
                owner: postData.userId,
            });

            await newPost.save();

           
            await newPost.populate("owner", "username profilePhoto name");

            const formattedPost = {
                ...newPost.toObject(),
                likesCount: newPost.likes ? newPost.likes.length : 0,
                commentsCount: newPost.commentsCount || 0,
                sharesCount: newPost.sharesCount || 0,
                isLiked: false
            };

            return formattedPost;
        } catch (error) {
            console.error("Error creating post:", error);
            throw new Error("Error creating post in the database");
        }
    },

    async getTimelineFeed(userId, page = 1, limit = 12) {
        try {
            const skip = (page - 1) * limit;
            const followingDocs = await Follow.find({ follower: userId }).select("following").lean();
            const followingIds = followingDocs.map(doc => doc.following);
            const authorIds = [...followingIds, userId];
            const [posts, totalCount] = await Promise.all([
                Post.find({
                    owner: { $in: authorIds },
                    isDeleted: { $ne: true },
                    isArchived: { $ne: true }
                })
                    .populate("owner", "username profilePhoto name")
                    .sort({ createdAt: -1 })
                    .skip(skip)
                    .limit(limit)
                    .lean(),
                Post.countDocuments({
                    owner: { $in: authorIds },
                    isDeleted: { $ne: true },
                    isArchived: { $ne: true }
                })
            ]);
            const formattedPosts = posts.map(post => {
                return {
                    ...post,
                    likesCount: post.likes ? post.likes.length : 0,
                    commentsCount: post.commentsCount || 0,
                    sharesCount: post.sharesCount || 0,
                    isLiked: post.likes ? post.likes.some(id => id.toString() === userId.toString()) : false
                };
            });

            return {
                posts: formattedPosts,
                totalCount,
                hasNextPage: skip + posts.length < totalCount
            };
        } catch (error) {
            console.error("Timeline Service Error:", error);
            throw new Error("Could not fetch timeline feed");
        }
    },

    async getFeed(userId) {


        try {
            const feed = await Post.find({ owner: userId }).sort({ createdAt: -1 });

            return feed;
        } catch (error) {
            console.error("Error fetching feed:", error);
            throw new Error("Error fetching feed from the database");
        }
    },

    async getPostsByHashtag(tag) {


        try {
            const posts = await Post.find({ hashtags: tag }).sort({ createdAt: -1 });

            return posts;
        } catch (error) {
            console.error("Error fetching posts by hashtag:", error);
            throw new Error("Error fetching posts by hashtag");
        }
    },

    async getAllPosts() {


        try {
            const posts = await Post.find().sort({ createdAt: -1 });

            return posts;
        } catch (error) {
            console.error("Error fetching all posts:", error);
            throw new Error("Error fetching all posts");
        }
    },

    async getUserPostsByUsername(username) {


        try {
            const user = await User.findOne({ username });
            if (!user) {

                return [];
            }

            const posts = await Post.find({ owner: user._id }).sort({ createdAt: -1 });

            return posts;
        } catch (error) {
            console.error("Error fetching user posts:", error);
            throw new Error("Error fetching user posts");
        }
    },

    async getSinglePost(postId) {

        try {
            const post = await Post.findById(postId);
            if (!post) {

                return null;
            }

            return post;
        } catch (error) {
            console.error("Error fetching post:", error);
            throw new Error("Error fetching post by ID");
        }
    },

    async deletePost(postId, userId) {
        try {
            const result = await Post.deleteOne({
                _id: postId,
                owner: userId
            });
            if (result.deletedCount === 0) {
                return false;
            }

            return true;
        } catch (error) {
            console.error("Error deleting post:", error);
            throw new Error("Error deleting post from the database");
        }
    },

    async toggleLike(postId, userId) {
        try {
            const post = await Post.findById(postId);
            if (!post) {
                console.log("Post not found:", postId);
                return {
                    message: "Post not found",
                    liked: false,
                    likesCount: 0
                };
            }

            const userIdStr = userId.toString();
            const alreadyLiked = post.likes.some(
                (like) => like.toString() === userIdStr
            );

            if (alreadyLiked) {
                post.likes = post.likes.filter(
                    (like) => like.toString() !== userIdStr
                );
            } else {
                post.likes.push(userId);
            }

            await post.save();

            return {
                message: alreadyLiked
                    ? "Post unliked successfully"
                    : "Post liked successfully",
                liked: !alreadyLiked,
                likesCount: post.likes.length,
            };
        } catch (error) {
            console.error("Error toggling like:", error);
            throw new Error("Error toggling like status");
        }
    },
    // Explore Feed - Shows posts from public accounts user is NOT following

    async getExploreFeed(userId, page = 1, limit = 20, excludeFollowing = false) {
    try {
        const skip = (page - 1) * limit;
        
        // Convert userId to ObjectId once
        const userObjectId = new mongoose.Types.ObjectId(userId);
        let excludedUserIds = [userObjectId]; // Always exclude own posts
        
        // If excludeFollowing is true, also exclude posts from followed users
        if (excludeFollowing) {
            const followingDocs = await Follow.find({ 
                follower: userId,
                status: "accepted"
            }).select("following").lean();
            
            const followingIds = followingDocs.map(doc => doc.following);
            excludedUserIds = [...excludedUserIds, ...followingIds];
        }
        
        // Aggregation pipeline
        const posts = await Post.aggregate([
            {
                $match: {
                    owner: { $nin: excludedUserIds },
                    isDeleted: { $ne: true },
                    isArchived: { $ne: true }
                }
            },
            {
                $lookup: {
                    from: "users",
                    localField: "owner",
                    foreignField: "_id",
                    as: "ownerDetails"
                }
            },
            {
                $unwind: "$ownerDetails"
            },
            {
                $match: {
                    "ownerDetails.isPrivate": false,
                    "ownerDetails.accountStatus": "active"
                }
            },
            {
                $addFields: {
                    likesCount: { $size: { $ifNull: ["$likes", []] } },
                    isLiked: {
                        $in: [userObjectId, { $ifNull: ["$likes", []] }]
                    }
                }
            },
            {
                $sort: { createdAt: -1 }
            },
            {
                $skip: skip
            },
            {
                $limit: limit
            },
            {
                $project: {
                    _id: 1,
                    mediaUrl: 1,
                    mediaType: 1,
                    caption: 1,
                    hashtags: 1,
                    likesCount: 1,
                    commentsCount: 1,
                    sharesCount: 1,
                    location: 1,
                    isLiked: 1,
                    createdAt: 1,
                    updatedAt: 1,
                    owner: {
                        _id: "$ownerDetails._id",
                        username: "$ownerDetails.username",
                        name: "$ownerDetails.name",
                        profilePhoto: "$ownerDetails.profilePhoto",
                        isVerified: "$ownerDetails.isVerified"
                    }
                }
            }
        ]);
        
        // Count total
        const totalCountPipeline = await Post.aggregate([
            {
                $match: {
                    owner: { $nin: excludedUserIds },
                    isDeleted: { $ne: true },
                    isArchived: { $ne: true }
                }
            },
            {
                $lookup: {
                    from: "users",
                    localField: "owner",
                    foreignField: "_id",
                    as: "ownerDetails"
                }
            },
            {
                $unwind: "$ownerDetails"
            },
            {
                $match: {
                    "ownerDetails.isPrivate": false,
                    "ownerDetails.accountStatus": "active"
                }
            },
            {
                $count: "total"
            }
        ]);
        
        const totalCount = totalCountPipeline[0]?.total || 0;

        return {
            posts,
            totalCount,
            currentPage: page,
            totalPages: Math.ceil(totalCount / limit),
            hasNextPage: skip + posts.length < totalCount,
            hasPrevPage: page > 1
        };
    } catch (error) {
        console.error("Explore Feed Service Error:", error);
        throw new Error("Could not fetch explore feed");
    }
},

    async getTrendingExploreFeed(userId, page = 1, limit = 20) {
        try {
            const skip = (page - 1) * limit;

            const followingDocs = await Follow.find({
                follower: userId,
                status: "accepted"
            }).select("following").lean();

            const followingIds = followingDocs.map(doc => doc.following);

            const sevenDaysAgo = new Date();
            sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

            const posts = await Post.aggregate([
                {
                    $match: {
                        owner: {
                            $nin: [...followingIds, new mongoose.Types.ObjectId(userId)]
                        },
                        isDeleted: { $ne: true },
                        isArchived: { $ne: true },
                        createdAt: { $gte: sevenDaysAgo }
                    }
                },
                {
                    $lookup: {
                        from: "users",
                        localField: "owner",
                        foreignField: "_id",
                        as: "ownerDetails"
                    }
                },
                {
                    $unwind: "$ownerDetails"
                },
                {
                    $match: {
                        "ownerDetails.isPrivate": false,
                        "ownerDetails.accountStatus": "active"
                    }
                },
                {
                    $addFields: {
                        likesCount: { $size: { $ifNull: ["$likes", []] } },
                        engagementScore: {
                            $add: [
                                { $size: { $ifNull: ["$likes", []] } },
                                { $multiply: ["$commentsCount", 2] },
                                { $multiply: ["$sharesCount", 3] }
                            ]
                        },
                        isLiked: {
                            $in: [new mongoose.Types.ObjectId(userId), { $ifNull: ["$likes", []] }]
                        }
                    }
                },
                {
                    $sort: { engagementScore: -1, createdAt: -1 }
                },
                {
                    $skip: skip
                },
                {
                    $limit: limit
                },
                {
                    $project: {
                        _id: 1,
                        mediaUrl: 1,
                        mediaType: 1,
                        caption: 1,
                        hashtags: 1,
                        likesCount: 1,
                        commentsCount: 1,
                        sharesCount: 1,
                        location: 1,
                        engagementScore: 1,
                        isLiked: 1,
                        createdAt: 1,
                        updatedAt: 1,
                        owner: {
                            _id: "$ownerDetails._id",
                            username: "$ownerDetails.username",
                            name: "$ownerDetails.name",
                            profilePhoto: "$ownerDetails.profilePhoto",
                            isVerified: "$ownerDetails.isVerified"
                        }
                    }
                }
            ]);

            // Count total
            const totalCountPipeline = await Post.aggregate([
                {
                    $match: {
                        owner: { $nin: [...followingIds, new mongoose.Types.ObjectId(userId)] },
                        isDeleted: { $ne: true },
                        isArchived: { $ne: true },
                        createdAt: { $gte: sevenDaysAgo }
                    }
                },
                {
                    $lookup: {
                        from: "users",
                        localField: "owner",
                        foreignField: "_id",
                        as: "ownerDetails"
                    }
                },
                {
                    $unwind: "$ownerDetails"
                },
                {
                    $match: {
                        "ownerDetails.isPrivate": false,
                        "ownerDetails.accountStatus": "active"
                    }
                },
                {
                    $count: "total"
                }
            ]);

            const totalCount = totalCountPipeline[0]?.total || 0;

            return {
                posts,
                totalCount,
                currentPage: page,
                totalPages: Math.ceil(totalCount / limit),
                hasNextPage: skip + posts.length < totalCount,
                hasPrevPage: page > 1
            };
        } catch (error) {
            console.error("Trending Explore Service Error:", error);
            throw new Error("Could not fetch trending explore feed");
        }
    }

};





module.exports = { postService };
