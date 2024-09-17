import React from 'react';
import { Link } from "react-router-dom";
import { FaArrowRightLong } from "react-icons/fa6";
import { FaUserCircle } from "react-icons/fa";
import { GoComment } from "react-icons/go";
import { CiHeart } from "react-icons/ci";

const TrendingPosts = ({ posts }) => {
  return (
    <div className="p-2 rounded-xl m-2 md:m-5 mb-16 md:mb-6 md:mt-24 bg-[#526b9e]">
      <Link to={"/app/trending"}>
        <h1 className="mb-4 text-2xl font-bold text-white text-center flex items-center justify-center">
          Trending Posts
          <FaArrowRightLong className="m-4 text-black cursor-pointer" size={25} />
        </h1>
      </Link>
      <div className="grid grid-cols-1 gap-4 text-sm md:text-xl max-h-[500px] overflow-y-auto">
        {posts.map((post) => (
          <div key={post._id} className="p-6 rounded-xl shadow-xl bg-white cursor-pointer mb-4">
            <div className="flex items-center mb-4">
              {post.user?.image ? (
                <img
                  src={post.user.image}
                  alt="User"
                  className="mr-2 w-10 h-10 rounded-full"
                />
              ) : (
                <FaUserCircle className="w-10 h-10 mr-2" />
              )}
              <p className="text-base font-semibold">{post.user?.name.split(" ")[0]}</p>
            </div>
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold">{post.title}</h3>
                <p className="text-sm">{post.description}</p>
              </div>
              {post.image && (
                <img
                  src={post.image}
                  alt="Post"
                  className="w-20 h-16 object-cover rounded-lg"
                />
              )}
            </div>
            <div className="flex items-center">
              <div className="flex items-center mr-4">
                <CiHeart className="text-red-500 mr-1" />
                <span className="">{post.likesCount}</span>
              </div>
              <div className="flex items-center">
                <GoComment className="text-blue-500 mr-1" />
                <span className="">{post.commentsCount}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default TrendingPosts;