const User = require("../models/userModel");
const Follow = require("../models/followModel");
const Post = require("../models/postModel");
const { asyncHandler } = require("../utils/utils.js");

exports.getMe = asyncHandler(async (req, res) => {
    const userId = req.user._id;

    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 10, 1), 100);
    const skip = (page - 1) * limit;

    try {
        const user = await User.findById(userId)
            .select("name username email dob termsAccepted profilePhoto bio isPrivate lastLogin createdAt")
            .populate({
                path: 'followers',
                select: 'follower',
                populate: {
                    path: 'follower',
                    select: 'username profilePhoto'
                }
            })
            .populate({
                path: 'following',
                select: 'following',
                populate: {
                    path: 'following',
                    select: 'username profilePhoto'
                }
            })
            .populate({
                path: 'posts',
                select: 'mediaUrl caption likesCount createdAt',
                options: {
                    skip,
                    limit,
                    sort: { createdAt: -1 }
                }
            })
            .lean();

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "Logged in user not found."
            });
        }
        const totalPosts = await Post.countDocuments({ user: userId });
        const followersList = (user.followers || []).map(f => f?.follower).filter(Boolean);
        const followingList = (user.following || []).map(f => f?.following).filter(Boolean);

        res.status(200).json({
            success: true,
            data: {
                user: {
                    ...user,
                    followers: followersList,
                    following: followingList,
                    posts: user.posts || [],
                    followersCount: followersList.length,
                    followingCount: followingList.length,
                    postsCount: user.posts?.length || 0,
                },
                pagination: {
                    totalPosts,
                    totalPages: Math.ceil(totalPosts / limit),
                    currentPage: page,
                    limit,
                }
            },
        });
    } catch (error) {
        console.error("Error fetching profile:", error);
        res.status(500).json({
            success: false,
            message: "An error occurred while fetching the profile.",
            error: error.message
        });
    }
});

exports.followUser = asyncHandler(async (req, res) => {
    const followerId = req.user._id;
    const followingId = req.params.id;

    if (followerId.toString() === followingId) {
        return res.status(400).json({ success: false, message: "You cannot follow yourself." });
    }

    const targetUser = await User.findById(followingId);
    if (!targetUser) {
        return res.status(404).json({ success: false, message: "User not found." });
    }

    const existingFollow = await Follow.findOne({
        follower: followerId,
        following: followingId
    });

    if (existingFollow) {
        return res.status(400).json({
            success: false,
            message: existingFollow.status === "pending" ? "Follow request already sent." : "Already following this user."
        });
    }

    const status = targetUser.isPrivate ? "pending" : "accepted";

    await Follow.create({
        follower: followerId,
        following: followingId,
        status
    });

    res.status(200).json({
        success: true,
        message: status === "pending" ? "Follow request sent." : "User followed successfully.",
        status
    });
});

exports.unfollowUser = asyncHandler(async (req, res) => {
    const followerId = req.user._id;
    const followingId = req.params.id;

    const result = await Follow.findOneAndDelete({
        follower: followerId,
        following: followingId
    });

    if (!result) {
        return res.status(400).json({ success: false, message: "You are not following this user." });
    }

    res.status(200).json({ success: true, message: "Action successful." });
});

exports.acceptFollowRequest = asyncHandler(async (req, res) => {
    const requestId = req.params.requestId; // The _id of the Follow document
    const userId = req.user._id;

    const follow = await Follow.findOneAndUpdate(
        { _id: requestId, following: userId, status: "pending" },
        { status: "accepted" },
        { new: true }
    );

    if (!follow) {
        return res.status(404).json({ success: false, message: "Follow request not found." });
    }

    res.status(200).json({ success: true, message: "Follow request accepted." });
});

exports.rejectFollowRequest = asyncHandler(async (req, res) => {
    const requestId = req.params.requestId;
    const userId = req.user._id;

    const follow = await Follow.findOneAndDelete({
        _id: requestId,
        following: userId,
        status: "pending"
    });

    if (!follow) {
        return res.status(404).json({ success: false, message: "Follow request not found." });
    }

    res.status(200).json({ success: true, message: "Follow request rejected." });
});

exports.searchUsers = asyncHandler(async (req, res) => {
    const { query } = req.query;
    const currentUserId = req.user?.id; // Get the logged-in user's ID
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 10, 1), 50);
    const skip = (page - 1) * limit;

    if (!query || query.trim().length === 0) {
        return res.status(200).json({
            success: true,
            data: { users: [], pagination: {} }
        });
    }

    const searchRegex = new RegExp(query.trim(), 'i');

    const filter = {
        $and: [
            { accountStatus: "active" },
            // ✅ EXCLUDE CURRENT USER: Only show profiles where ID is NOT the current user's ID
            ...(currentUserId ? [{ _id: { $ne: currentUserId } }] : []),
            {
                $or: [
                    { username: { $regex: searchRegex } },
                    { name: { $regex: searchRegex } }
                ]
            }
        ]
    };

    const [users, totalResults] = await Promise.all([
        User.find(filter)
            .select("name username profilePhoto isVerified bio")
            .limit(limit)
            .skip(skip)
            .lean(),
        User.countDocuments(filter)
    ]);

    res.status(200).json({
        success: true,
        count: users.length,
        pagination: {
            totalResults,
            totalPages: Math.ceil(totalResults / limit),
            currentPage: page,
            hasNextPage: page * limit < totalResults
        },
        data: users
    });
});

exports.getUserByUsername = asyncHandler(async (req, res) => {
    const username = req.params.username?.trim();
    const loggedInUserId = req.user?._id;

    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 12, 1), 50);
    const skip = (page - 1) * limit;

    if (!username) {
        return res.status(400).json({ success: false, message: "Username is required." });
    }

    // 1. Find the user
    const user = await User.findOne({ username: new RegExp(`^${username}$`, "i") })
        .select("name username profilePhoto bio isPrivate accountStatus createdAt")
        .lean();

    if (!user || user.accountStatus !== "active") {
        return res.status(404).json({ success: false, message: "User not found." });
    }

    const isOwnProfile = loggedInUserId?.toString() === user._id.toString();

    const [followersCount, followingCount, postsCount, followRecord] = await Promise.all([
        Follow.countDocuments({ following: user._id }),
        Follow.countDocuments({ follower: user._id }),
        Post.countDocuments({ owner: user._id, isDeleted: false }), // Ensure we only count non-deleted posts
        loggedInUserId ? Follow.findOne({ follower: loggedInUserId, following: user._id }).lean() : null
    ]);

    const isFollowing = !!followRecord;
    const shouldHideContent = user.isPrivate && !isOwnProfile && !isFollowing;

    let posts = [];
    if (!shouldHideContent) {
        posts = await Post.find({ owner: user._id, isDeleted: false })
            // UPDATED: Added hashtags, sharesCount, and location to the select string
            .select("mediaUrl mediaType caption likes hashtags sharesCount location commentsCount createdAt")
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .lean();

        // Process posts to include counts and social status
        posts = posts.map(post => ({
            ...post,
            likesCount: post.likes ? post.likes.length : 0,
            // Check if the current logged-in user liked this post
            isLiked: loggedInUserId ? post.likes?.some(id => id.toString() === loggedInUserId.toString()) : false,
            // We remove the full likes array to keep the response size small
            likes: undefined
        }));
    }

    res.status(200).json({
        success: true,
        data: {
            ...user,
            stats: {
                followersCount,
                followingCount,
                postsCount
            },
            relationships: {
                isOwnProfile,
                isFollowing,
                canViewContent: !shouldHideContent
            },
            posts,
            pagination: {
                currentPage: page,
                hasNextPage: skip + posts.length < postsCount,
                totalPages: Math.ceil(postsCount / limit)
            }
        }
    });
});


// Updating data
exports.updateProfile = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    const { name, username, bio, isPrivate } = req.body;

    // Validate that at least one field is being updated
    if (!name && !username && bio === undefined && isPrivate === undefined) {
        return res.status(400).json({
            success: false,
            message: "Please provide at least one field to update."
        });
    }

    const updateData = {};

    // Validate and add name
    if (name !== undefined) {
        const trimmedName = name.trim();
        if (trimmedName.length === 0) {
            return res.status(400).json({
                success: false,
                message: "Name cannot be empty."
            });
        }
        if (trimmedName.length > 50) {
            return res.status(400).json({
                success: false,
                message: "Name must be less than 50 characters."
            });
        }
        updateData.name = trimmedName;
    }

    // Validate and add username
    if (username !== undefined) {
        const trimmedUsername = username.trim().toLowerCase();

        if (trimmedUsername.length === 0) {
            return res.status(400).json({
                success: false,
                message: "Username cannot be empty."
            });
        }

        // Username format validation (alphanumeric, underscore, dot, 3-30 chars)
        const usernameRegex = /^[a-z0-9_.]{3,30}$/;
        if (!usernameRegex.test(trimmedUsername)) {
            return res.status(400).json({
                success: false,
                message: "Username must be 3-30 characters and contain only letters, numbers, underscores, or dots."
            });
        }

        // Check if username is already taken by another user
        const existingUser = await User.findOne({
            username: trimmedUsername,
            _id: { $ne: userId }
        });

        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: "Username is already taken."
            });
        }

        updateData.username = trimmedUsername;
    }

    // Validate and add bio
    if (bio !== undefined) {
        const trimmedBio = bio.trim();
        if (trimmedBio.length > 150) {
            return res.status(400).json({
                success: false,
                message: "Bio must be less than 150 characters."
            });
        }
        updateData.bio = trimmedBio;
    }

    // Add isPrivate (boolean)
    if (isPrivate !== undefined) {
        if (typeof isPrivate !== "boolean") {
            return res.status(400).json({
                success: false,
                message: "isPrivate must be a boolean value."
            });
        }
        updateData.isPrivate = isPrivate;
    }

    // Update the user
    const updatedUser = await User.findByIdAndUpdate(
        userId,
        { $set: updateData },
        { new: true, runValidators: true }
    ).select("name username profilePhoto bio isPrivate createdAt");

    if (!updatedUser) {
        return res.status(404).json({
            success: false,
            message: "User not found."
        });
    }

    res.status(200).json({
        success: true,
        message: "Profile updated successfully.",
        data: updatedUser
    });
});


// Sugestions Code

exports.getSuggestedUsers = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    const limit = Math.min(parseInt(req.query.limit) || 10, 20);

    const followingDocs = await Follow.find({ 
        follower: userId, 
        status: { $in: ["accepted", "pending"] } 
    }).select("following");
    
    const followingIds = followingDocs.map(f => f.following);
    const excludeIds = [...followingIds, userId];

    const suggestions = await Follow.aggregate([
        {
            $match: {
                follower: { $in: followingIds },
                following: { $nin: excludeIds },
                status: "accepted"
            }
        },
        {
            $group: {
                _id: "$following",
                mutualCount: { $sum: 1 }
            }
        },
        { $sort: { mutualCount: -1 } },
        { $limit: limit },
        {
            $lookup: {
                from: "users",
                localField: "_id",
                foreignField: "_id",
                as: "userDetails"
            }
        },
        { $unwind: "$userDetails" },
        {
            $match: {
                "userDetails.accountStatus": "active"
            }
        },
        {
            $project: {
                _id: "$userDetails._id",
                username: "$userDetails.username",
                name: "$userDetails.name",
                profilePhoto: "$userDetails.profilePhoto",
                mutualCount: 1
            }
        }
    ]);

    if (suggestions.length < limit) {
        const remainingLimit = limit - suggestions.length;
        const currentSuggestionIds = suggestions.map(s => s._id);

        const fallbacks = await User.find({
            _id: { $nin: [...excludeIds, ...currentSuggestionIds] },
            accountStatus: "active"
        })
        .select("username name profilePhoto")
        .sort({ createdAt: -1 })
        .limit(remainingLimit)
        .lean();

        suggestions.push(...fallbacks.map(f => ({ 
            ...f, 
            mutualCount: 0 
        })));
    }

    res.status(200).json({
        success: true,
        data: suggestions
    });
});