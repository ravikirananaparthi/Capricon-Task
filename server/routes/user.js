import express from "express";

import {
  createNewposts,
  feed,
  getMyprofile,
  getUserPosts,
  googleLogin,
  login,
  logout,
  newGoogle,
  register,
  trend,
} from "../controllers/user.js";

import { Post } from "../models/post.js";
import { User } from "../models/user.js";
import { isAuthenticated } from "../middlewares/auth.js";


const router = express.Router();

router.post("/posts", isAuthenticated,createNewposts);

router.post("/new", register);

router.post("/login", login);

router.get("/logout", logout);

router.get("/me", isAuthenticated, getMyprofile);

router.get("/dashboard", isAuthenticated, getUserPosts);

router.get("/viewposts", isAuthenticated, feed);
router.get("/trendingposts", isAuthenticated, trend);

router.get("/new/google", isAuthenticated, newGoogle);

router.get("/google-login",isAuthenticated, googleLogin);

router.post("/profilepic", isAuthenticated, async (req, res) => {
  const { imageUrl } = req.body;

  try {
    const user = await User.findById(req.user._id);
    console.log(user);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    user.image = imageUrl;
    await user.save();

    res.status(200).json({ message: "Profile picture updated successfully" });
  } catch (error) {
    console.error("Error updating profile picture:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});


router.get("/:userId", async (req, res) => {
  const userId = req.params.userId;

  User.findById(userId)
    .then((user) => {
      if (!user) {
        return res
          .status(404)
          .json({ success: false, message: "User not found" });
      }
      // Return the user data
      res.status(200).json({ success: true, user });
    })
    .catch((error) => {
      console.error("Error fetching user:", error);
      res
        .status(500)
        .json({ success: false, message: "Internal server error" });
    });
});

// Export the router
export default router;
