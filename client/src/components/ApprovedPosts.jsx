import React from 'react';
import { FaUserCircle, FaShare } from "react-icons/fa";
import { GoComment } from "react-icons/go";
import { FcLike } from "react-icons/fc";
import moment from "moment";

const ApprovedPosts = ({ posts }) => {
  return (
    <div className="grid grid-cols-1 gap-4 text-sm md:text-xl">
      {posts.length === 0 ? (
        <p className="text-center">No approved posts found.</p>
      ) : (
        [...posts].reverse().map((post) => (
          <div key={post._id} className="p-6 rounded-xl shadow-xl bg-white cursor-pointer">
            <div className="flex items-center mb-2">
              {post.user?.image ? (
                <img
                  src={post.user.image}
                  alt={post.user.name}
                  className="h-12 w-12 md:h-12 md:w-12 mr-2 rounded-full object-cover"
                />
              ) : (
                <FaUserCircle className="h-12 w-12 mr-2" />
              )}
              <p className="text-lg font-semibold">{post.user.name}</p>
              <p className="text-sm ml-auto">{moment(post.createdAt).fromNow()}</p>
            </div>
            <h2 className="text-lg font-semibold mb-2">{post.title}</h2>
            <p className="mb-4">{post.description}</p>
            {post.image && (
              <div className="aspect-auto w-full mb-4">
                <img
                  src={post.image}
                  alt="Post"
                  className="object-cover w-full h-48 rounded-lg"
                />
              </div>
            )}
            <div className="flex items-center justify-around">
              <div className="flex items-center">
                <FcLike size={24} className="mr-2" />
                <p className="text-gray-500">3</p>
              </div>
              <div className="flex items-center">
                <GoComment size={20} className="mr-2 text-blue-500" />
                <p className="text-gray-500">Comment</p>
              </div>
              <FaShare size={20} className="text-blue-500" />
            </div>
          </div>
        ))
      )}
    </div>
  );
};

export default ApprovedPosts;