import { io } from "../app.js";

import { Post } from "../models/post.js";

export const userposts = async (req, res) => {
  const userId = req.params.userId;

  try {
    const posts = await Post.find({ user: userId })
      .populate("user")
      .populate("comments.postedBy")
      .exec();

    res.status(200).json({ success: true, posts });
  } catch (error) {
    console.error("Error fetching user posts:", error);
    res
      .status(500)
      .json({ success: false, message: "Error fetching user posts" });
  }
};

export const displaypost = async (req, res) => {
  try {
    const postId = req.params.postId;

    const post = await Post.findById(postId)
      .populate({
        path: "comments",
        populate: {
          path: "postedBy",
          select: "name image", // select only the 'name' field from the user document
        },
      })
      .populate("user", "name image");
    if (!post) {
      return res
        .status(404)
        .json({ success: false, message: "Post not found" });
    }
    res.status(200).json({ success: true, post });
  } catch (error) {
    console.error("Error fetching post:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
};
export const comment = async (req, res, next) => {
  const { comment } = req.body;

  try {
    const postComment = await Post.findByIdAndUpdate(
      req.params.postId,

      {
        $push: { comments: { text: comment, postedBy: req.user._id } },
      },
      { new: true }
    );
    const post = await Post.findById(postComment._id).populate(
      "comments.postedBy",
      "name email image"
    );


    res.status(200).json({
      success: true,
      post,
    });
  } catch (error) {
    console.error(error);
    next(error);
  }
};


export const like = async (req, res, next) => {
  try {
    const post = await Post.findByIdAndUpdate(
      req.params.postId,
      {
        $addToSet: { likes: req.user._id },
      },
      { new: true }
    )
      .populate({
        path: "comments",
        populate: { path: "postedBy", select: "name" }, // Populate the 'postedBy' field within the 'comments' array
      })
      .populate("user", ["name", "image"]);

    io.emit("add-like", post);
    console.log(post);

    res.status(200).json({
      success: true,
      post,
    });
  } catch (error) {
    next(error);
  }
};
export const unlike = async (req, res, next) => {
  try {
    const post = await Post.findByIdAndUpdate(
      req.params.postId,
      {
        $pull: { likes: req.user._id },
      },
      { new: true }
    )
      .populate({
        path: "comments",
        populate: { path: "postedBy", select: "name" },
      })
      .populate("user", ["name", "image"]);

    io.emit("remove-like", post);

    // Send the response with the updated post
    res.status(200).json({
      success: true,
      post,
    });
  } catch (error) {
    next(error);
  }
};

export const search = async (req, res) => {
  try {
    const { title } = req.query;
    const regex = new RegExp(title, "i");

    const posts = await Post.find({ title: regex });

    res.status(200).json(posts);
  } catch (error) {
    console.error("Error searching posts:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};
export const deletePost = async (req, res, next) => {
  try {
    const postId = req.params.postId;

    const deletedPost = await Post.findByIdAndDelete(postId);

    if (!deletedPost) {
      return res.status(404).json({ message: "Post not found" });
    }

    res.status(200).json({ message: "Post deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
};

export const trending = async (req, res) => {
  try {
    const trendingPosts = await Post.find()
      .sort({ likes: -1 })
      .limit(4)
      .populate("user", "name image")
      .populate("likes")
      .populate("comments")
      .populate('tof')
      .populate('image');

    const postsWithCounts = trendingPosts.map((post) => ({
      _id: post._id,
      title: post.title,
      description: post.description,
      user: post.user,
      image: post.image,
      tof: post.tof,
      likesCount: post.likes.length,
      commentsCount: post.comments.length,
    }));

    res.status(200).json(postsWithCounts);
  } catch (error) {
    console.error("Error fetching trending posts:", error);
    res.status(500).json({ error: "Could not fetch trending posts" });
  }
};




// Middleware to check if the user is an admin
export const isAdmin = (req, res, next) => {
  if (req.user.role === "admin") {
    next();
  } else {
    res.status(403).json({ success: false, message: "Access denied. Admins only." });
  }
};

// Admin approval or rejection of a post
export const approvePost = async (req, res) => {
  const { postId } = req.params;
  const { status,adminComments} = req.body; // status can be 'approved' or 'rejected'

  if (!["approved", "rejected"].includes(status)) {
    return res.status(400).json({ success: false, message: "Invalid status" });
  }

  try {
    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).json({ success: false, message: "Post not found" });
    }

    // Update post status and add admin comments if any
    post.status = status;
    post.adminComments = adminComments || "";
    await post.save();

    res.status(200).json({
      success: true,
      message: `Post has been ${status}`,
      post,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
};


export const getPendingPosts = async (req, res) => {
  try {
    // Find posts with the status 'pending'
    const pendingPosts = await Post.find({ status: "pending" }).populate("user", "name email");

    if (pendingPosts.length === 0) {
      return res.status(200).json({ success: true, message: "No pending posts found", posts: [] });
    }

    res.status(200).json({
      success: true,
      posts: pendingPosts,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
};