import React, { useEffect, useState } from "react";
import axios from "axios";
import { server } from "../main";
import { CiClock1 } from "react-icons/ci"; // Pending icon
import { AiOutlineCheckCircle, AiOutlineCloseCircle } from "react-icons/ai"; // Approved and Rejected icons

const UserDashboard = () => {
  const [posts, setPosts] = useState([]);

  // Fetch user's posts on component mount
  useEffect(() => {
    const fetchPosts = async () => {
      try {
        const { data } = await axios.get(`${server}users/dashboard`, {
          headers: {
            "Content-Type": "application/json",
          },
          withCredentials: true,
        });
        setPosts(data.posts);
      } catch (error) {
        console.error("Error fetching posts", error);
      }
    };
    fetchPosts();
  }, []);

  // Helper function to render the status icon
  const renderStatusIcon = (status) => {
    switch (status) {
      case "approved":
        return (
          <AiOutlineCheckCircle className="text-green-500" size={24} title="Approved" />
        );
      case "rejected":
        return (
          <AiOutlineCloseCircle className="text-red-500" size={24} title="Rejected" />
        );
      case "pending":
      default:
        return <CiClock1 className="text-yellow-500" size={24} title="Pending" />;
    }
  };

  return (
    <div className="min-h-screen bg-white">
      <div className="container mx-auto p-4">
        <h1 className="text-2xl font-bold mb-4">My Blog Posts</h1>
        {posts.length === 0 ? (
          <p>No posts found.</p>
        ) : (
          <div className="grid gap-6 sm:grid-cols-1 md:grid-cols-2 lg:grid-cols-3">
            {posts.map((post) => (
              <div
                key={post._id}
                className="bg-white border border-gray-200 rounded-lg shadow-lg p-4 hover:bg-gray-200 transition duration-300 ease-in-out"
              >
                <h2 className="text-xl font-semibold mb-2">{post.title}</h2>
                <div className="flex items-center mb-4">
                  {renderStatusIcon(post.status)}
                  <span className="ml-2 text-gray-700">
                    {post.status.charAt(0).toUpperCase() + post.status.slice(1)}
                  </span>
                </div>
                <p className="text-gray-600">
                  Admin Comments: {post.adminComments || "No comments"}
                </p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default UserDashboard;
