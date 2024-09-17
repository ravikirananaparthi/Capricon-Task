import React, { useState, useEffect, useContext } from "react";
import axios from "axios";
import { Navigate } from "react-router-dom";
import { Context, server } from "../main";

import LeftSidebar from "../components/Sidebar";
import ApprovedPosts from "../components/ApprovedPosts";
import TrendingPosts from "../components/TrendingPosts";

const Feed = () => {
  const [approvedPosts, setApprovedPosts] = useState([]);
  const { isAuthenticated } = useContext(Context);

  useEffect(() => {
    const fetchApprovedPosts = async () => {
      try {
        const { data } = await axios.get(`${server}users/viewposts`, {
          headers: {
            "Content-Type": "application/json",
          },
          withCredentials: true,
        });
        setApprovedPosts(data.posts);
        console.log(data.posts);
      } catch (error) {
        console.error("Error fetching approved posts", error);
      }
    };

    fetchApprovedPosts();
  }, []);

  const trendingPosts = [
    {
      _id: 1,
      user: { name: "Jane Smith", image: "" },
      title: "Flutter experience",
      description: "",
      image: 'https://firebasestorage.googleapis.com/v0/b/devfinds-ravi8130.appspot.com/o/flutter.png?alt=media&token=b9743caa-aa98-4560-b39a-d75dd301aa29',
    },
    {
      _id: 2,
      user: { name: "Jack", image: "" },
      title: "My React Native experience",
      description: "In the past 5 months working with React Native, I've built mobile UIs, used my JavaScript skills for app logic, integrated libraries, and even tapped into native functionalities for a smooth, performant app. It's been a continuous learning experience!",
      image: "https://firebasestorage.googleapis.com/v0/b/devfinds-ravi8130.appspot.com/o/React-Native.png?alt=media&token=7dc3c2c5-7370-475c-8769-4973fcc09f8c",
    },
  ];

  if (!isAuthenticated) return <Navigate to={"/"} />;

  return (
    <div className="bg-gradient-to-r from-[#4b6cb7] to-[#182848]">
      <div className="sm:overflow-y-auto md:overflow-y-hidden md:flex flex-col md:flex-row h-screen">
        <LeftSidebar />

        <div className="right flex-1 overflow-y-auto md:h-auto md:w-1/3">
          <div className="p-2 md:p-4 rounded-xl m-1 md:m-5 mb-16 md:mb-6 md:mt-20">
            <h1 className="mb-4 text-2xl font-bold text-center text-white">
              For You
            </h1>
            <ApprovedPosts posts={approvedPosts} />
          </div>
        </div>

        <div id="trending" className="hidden md:block md:w-1/4 m-1">
          <TrendingPosts posts={trendingPosts} />
        </div>
      </div>
    </div>
  );
};

export default Feed;