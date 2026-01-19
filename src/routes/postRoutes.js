const express = require("express");
const router = express.Router();
const postController = require("../controllers/postController");
const { authProtect } = require("../middleware/authMiddleware");

router.use((req, res, next) => {
    console.log(`[Router Debug] Incoming request: ${req.method} ${req.originalUrl}`);
    next();
});

router.use(authProtect());

router.post(
    "/create", 
    postController.uploadMiddleware, 
    postController.createPost        
);
router.get("/timeline", postController.getTimelineFeed);
router.get("/feed", postController.getFeed);
router.get("/explore/trending", postController.getTrendingExploreFeed);
router.get("/explore", postController.getExploreFeed);
router.get("/hashtag/:tag", postController.getPostsByHashtag);
router.get("/:id", postController.getPostById);
router.get("/user/:username", postController.getUserPosts);
router.patch("/:id", postController.updatePost);
router.delete("/:id", postController.deletePost);
router.post("/:id/like", postController.toggleLike);
router.patch("/:id/archive", postController.toggleArchive);

module.exports = router;