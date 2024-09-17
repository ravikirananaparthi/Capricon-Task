import express from "express";

import { isAuthenticated } from "../middlewares/auth.js";
import { Post } from "../models/post.js";
import {
  approvePost,
  comment,
  deletePost,
  displaypost,
  getPendingPosts,
  isAdmin,
  like,
  trending,
  unlike,
  userposts,
} from "../controllers/post.js";

const router = express.Router();


router.put("/admin/approve/:postId", isAuthenticated, isAdmin, approvePost  );
router.get("/admin/pending-posts", isAuthenticated,  isAdmin, getPendingPosts);

router.get('/trendingpost',isAuthenticated,trending);
router.get("/post/:postId", displaypost);
router.get("/user/:userId", isAuthenticated, userposts);


router.post("/comment/post/:postId", isAuthenticated, comment);

// Route for liking a post
router.put("/like/post/:postId", isAuthenticated, like);
router.put("/unlike/post/:postId", isAuthenticated, unlike);
router.delete("/delete/:postId",isAuthenticated,deletePost);

export default router;