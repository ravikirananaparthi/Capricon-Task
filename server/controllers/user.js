import { User } from "../models/user.js";
import bcrypt from "bcrypt";
import { sendCookie } from "../utils/features.js";
import ErrorHandler from "../middlewares/errorHandling.js";
import { Post } from "../models/post.js";
import admin from "firebase-admin";
import { getAuth } from "firebase-admin/auth";



export const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email }).select("+password");

    if (!user) return next(new ErrorHandler("Invalid User or Password", 400));

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch)
      return next(new ErrorHandler("Invalid User or Password", 400));
    else {
      user.status = "online";
      await user.save();
      sendCookie(user, res, `Welcome back ${user.name}`, 200);
    }
  } catch (error) {
    next(error);
  }
};

export const register = async (req, res, next) => {
  try {
    const {
      name,
      email,
      password,
      image,
      programmingExperience,
      learnedTechnologies,
    } = req.body;

    let img = null;
    if (image != null) {
      img = image;
    }
    let user = await User.findOne({ email });

    if (user) return next(new ErrorHandler("User AllReady Exists", 400));

    const hashedPassword = await bcrypt.hash(password, 10);

    user = await User.create({
      name,
      email,
      password: hashedPassword,
      image: img,
      programmingExperience,
      learnedTechnologies,
    });
    console.log(user);
    sendCookie(user, res, "Registered successfully", 201);
  } catch (error) {
    next(error);
  }
};

export const createNewposts = async (req, res) => {
  const { title, description, image, tof } = req.body;
  const userId = req.user.id; // Assuming the user info is extracted from JWT or session

  try {
    // Create a new post with the status set to 'pending' for admin approval
    const newPost = await Post.create({
      title,
      description,
      image,
      tof,
      user: userId,
      status: "pending", // Post starts as 'pending'
    });

    // Update the user's posts list by adding this new post
    const user = await User.findById(userId);
    if (user) {
      user.blogs.push(newPost._id);
      await user.save();
    }

    res.status(201).json({
      success: true,
      message: "New post created successfully and is pending approval!",
      post: newPost,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
};

export const getUserPosts = async (req, res) => {
  const userId = req.user.id;

  try {
    const posts = await Post.find({ user: userId }).sort({ createdAt: -1 });
    res.status(200).json({
      success: true,
      posts,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
};


export const getMyprofile = (req, res) => {
  res.status(200).json({
    success: true,
    user: req.user,
  });
};


export const logout = (req, res) => {
  res
    .status(200)
    .cookie("token", "", {
      expires: new Date(Date.now()),
      sameSite: "none",
      secure: true,
    })
    .json({
      success: true,
      user: req.user,
    });
};

export const feed = async (req, res, next) => {
  try {
    const approvedPosts = await Post.find({ status: 'approved' })
    .populate('user', 'name'); 
    res.status(200).json({ success: true, posts: approvedPosts });
  } catch (error) {
    console.error("Error fetching approved posts", error);
    res.status(500).json({ success: false, message: "Error fetching approved posts" });
  }
};

export const newGoogle = async (req, res, next) => {
  try {
    const { name, email, password, image, programmingExperience, learnedTechnologies, token } = req.body;
    console.log(req.body);
    let img=null;
    if (image===null){
      image=img;
    }
    // Verify ID token using Firebase Admin SDK
    const decodedToken = await getAuth().verifyIdToken(token);
    console.log(decodedToken);
    // Check for existing user with the same email
    let user= await User.findOne({ email }).select('socialauth');
    console.log(user);
    if (user) {
      if (!user.socialauth) {
        return res.status(403).json({
          error: 'This email is signed up without Google (Login with Email and password)'
        });
      }
      // User already exists and signed up with Google
      return res.json({ message: 'User already exists with Google sign-in' });
    }

    
     user = new User({
      name,
      email,
      password,
      image,
      programmingExperience,
      learnedTechnologies,
      socialauth:true,
    });
    await user.save();
    const tokeen = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: "2 days" });

    res.json({ success: true, message: 'Registered successfully', tokeen });
  } catch (err) {
    console.error(err); 
    if (err.code === 'auth/invalid-token') {
      return res.status(401).json({ error: 'Invalid Google sign-in token' });
    } else {
      return res.status(500).json({ error: 'An error occurred during registration' });
    }
  }
};


export const googleLogin = async (req, res, next) => {
  try {
    const { token } = req.body;

  
    const decodedToken = await admin.auth().verifyIdToken(token);
    console.log(decodedToken);

   
    const user = await User.findOne({ email: decodedToken.email }).select('socialauth');
    console.log(user);

    if (!user) {
     
      return res.status(404).json({ error: 'User not found with this email' });
    }

    if (!user.socialauth) {
      return res.status(403).json({
        error: 'This email is signed up without Google (Login with Email and password)'
      });
    }

  
    const jwtToken = generateJWT(user._id);

    res.json({ success: true, message: 'Logged in successfully', token: jwtToken });
  } catch (err) {
    console.error(err);
    if (err.code === 'auth/invalid-token') {
      return res.status(401).json({ error: 'Invalid Google sign-in token' });
    } else {
      return res.status(500).json({ error: 'An error occurred during login' });
    }
  }
};






export const trend = async (req, res, next) => {
  try {
    const posts = await Post.aggregate([
      {
        $lookup: {
          from: "users",
          localField: "user",
          foreignField: "_id",
          as: "user",
        },
      },
      {
        $addFields: {
          likesCount: { $size: "$likes" },
        },
      },
      {
        $sort: { likesCount: -1 },
      },
      {
        $project: {
          _id: 1,
          title: 1,
          description: 1,
          image: 1,
          createdAt: 1,
          tof: 1, // Include the 'tof' field
          user: { $arrayElemAt: ["$user", 0] },
          likesCount: 1,
          commentsCount: { $size: "$comments" },
        },
      },
    ]);

    res.status(200).json(posts);
  } catch (error) {
    console.error("Error fetching posts:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};
