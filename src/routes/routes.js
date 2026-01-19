const express = require("express");
const authRoutes = require("./authRoutes");
const postRoutes = require("./postRoutes");
const userRoutes = require("./userRoutes");

const router = express.Router();

router.use("/auth", authRoutes);
router.use("/post", postRoutes);
router.use("/user", userRoutes);

router.get("/", (req, res) => {
  res.send("Welcome to the API");
});

module.exports = router;
    
