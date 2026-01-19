const express = require("express");
const router = express.Router();
const { authProtect } = require("../middleware/authMiddleware"); 
const userController = require("../controllers/userController"); 

router.get("/me", authProtect(), userController.getMe); 
router.post("/follow/:id", authProtect(), userController.followUser);
router.delete("/unfollow/:id", authProtect(), userController.unfollowUser);
router.get("/search", authProtect(), userController.searchUsers);
router.get("/profile/:username", authProtect(), userController.getUserByUsername);
router.put("/profile", authProtect(), userController.updateProfile);
router.get("/suggestions", authProtect(), userController.getSuggestedUsers);
module.exports = router;