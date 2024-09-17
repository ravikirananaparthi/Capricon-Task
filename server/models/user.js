import mongoose from "mongoose";



const schema = new mongoose.Schema(
  {
    // Existing fields
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, select: false },
    socialauth: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
    image: { type: String },
    status: { type: String, default: "online" },
    searchHistory: [String],
    programmingExperience: {
      type: String,
      enum: ["0 years", "1 year", "2 years", "3 years", "4+ years"],
      required: true,
    },
    learnedTechnologies: { type: [String], required: true },

    // New fields for the assignment
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },
    blogs: [{ type: mongoose.Schema.Types.ObjectId, ref: "Blog" }],
  },
  { minimize: false }
);

export const User = mongoose.model("User", schema);
