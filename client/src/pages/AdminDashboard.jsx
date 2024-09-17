import React, { useEffect, useState } from "react";
import axios from "axios";
import { GoXCircle } from "react-icons/go"; // Reject icon
import { LuCheckCircle } from "react-icons/lu"; // Approve icon
import { FaUserCircle } from "react-icons/fa"; // User icon
import { server } from "../main";
import { toast } from "react-hot-toast";
const AdminDashboard = () => {
  const [pendingPosts, setPendingPosts] = useState([]);
  const [commentsPanel, setCommentsPanel] = useState({}); // State to manage comment panels
  const [adminComments, setAdminComments] = useState({}); // State for admin comments per post

  // Fetch posts that are pending approval
  useEffect(() => {
    const fetchPendingPosts = async () => {
      try {
        const { data } = await axios.get(`${server}posts/admin/pending-posts`, {
          headers: {
            "Content-Type": "application/json",
          },
          withCredentials: true,
        });
        setPendingPosts(data.posts);
      } catch (error) {
        console.error("Error fetching posts", error);
      }
    };
    fetchPendingPosts();
  }, []);

  // Handle approve/reject with optional comments
  const handleApproval = async (postId, status, title) => {
    try {
      const comments = adminComments[postId] || ""; // Get comments for the post if provided
      await axios.put(
        `${server}posts/admin/approve/${postId}`,
        { status, comments },
        {
          headers: {
            "Content-Type": "application/json",
          },
          withCredentials: true,
        }
      );
      setPendingPosts(pendingPosts.filter((post) => post._id !== postId)); // Remove from list
      toast.success(`Post "${title}" has been ${status}`); // Toast notification
    } catch (error) {
      console.error("Error approving post", error);
      toast.error("Something went wrong while updating the post.");
    }
  };

  // Toggle comments panel for a specific post
  const toggleCommentsPanel = (postId) => {
    setCommentsPanel((prev) => ({
      ...prev,
      [postId]: !prev[postId],
    }));
  };

  // Handle comment input change for a specific post
  const handleCommentChange = (postId, value) => {
    setAdminComments((prev) => ({
      ...prev,
      [postId]: value,
    }));
  };

  return (
    <div className="bg-white min-h-screen flex flex-col items-center">
      <div className="container mx-auto p-4 bg-white rounded-lg shadow-md">
        <h1 className="text-3xl font-bold mb-8 text-center">Admin Dashboard</h1>
        {pendingPosts.length === 0 ? (
          <p className="text-center">No pending posts found.</p>
        ) : (
          <div className="w-full max-w-2xl">
            {pendingPosts.map((post) => (
              <div
                key={post._id}
                className="bg-white border border-gray-300 p-4 mb-6 rounded-lg shadow-lg"
              >
                {/* User Icon and Name */}
                <div className="flex items-center mb-4">
                  <FaUserCircle className="text-3xl mr-3" />
                  <h2 className="text-lg font-semibold">{post.user.name}</h2>
                </div>

                {/* Post Content */}
                <div className="mb-4">
                  <p className="text-xl font-semibold mb-2">{post.title}</p>
                  <p className="text-gray-700">{post.description}</p>
                </div>

                {/* Approve/Reject Buttons */}
                <div className="flex justify-between items-center">
                  <button
                    className="bg-green-500 text-white px-4 py-2 rounded-md hover:bg-green-600 flex items-center"
                    onClick={() =>
                      handleApproval(post._id, "approved", post.title)
                    }
                  >
                    <LuCheckCircle className="mr-2" /> Approve
                  </button>
                  <button
                    className="bg-red-500 text-white px-4 py-2 rounded-md hover:bg-red-600 flex items-center"
                    onClick={() =>
                      handleApproval(post._id, "rejected", post.title)
                    }
                  >
                    <GoXCircle className="mr-2" /> Reject
                  </button>
                  <button
                    className="text-blue-500 hover:underline"
                    onClick={() => toggleCommentsPanel(post._id)}
                  >
                    {commentsPanel[post._id] ? "Hide Comments" : "Add Comments"}
                  </button>
                </div>

                {/* Comments Panel */}
                {commentsPanel[post._id] && (
                  <div className="mt-4">
                    <textarea
                      placeholder="Admin Comments"
                      value={adminComments[post._id] || ""}
                      onChange={(e) =>
                        handleCommentChange(post._id, e.target.value)
                      }
                      className="w-full p-2 border rounded-md"
                    />
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default AdminDashboard;
