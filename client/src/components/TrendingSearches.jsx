import React from 'react';
import { RiFireFill } from "react-icons/ri";
import { IoTrendingUp } from "react-icons/io5";

const TrendingSearches = () => {
  const trendingTopics = ["Nodejs", "React"];

  return (
    <div className="w-[15rem]">
      <div className="p-4 text-white">
        <div className="flex flex-row">
          <RiFireFill size={25} className="mr-2 text-orange-500" />
          <p className="text-sm lg:text-base text-white">Trending Search</p>
        </div>
        {trendingTopics.map((topic, index) => (
          <p key={index} className="flex items-center mb-2 text-sm lg:text-base rounded-lg hover:bg-slate-500">
            <IoTrendingUp size={25} className="mr-2" />
            <button>{topic}</button>
          </p>
        ))}
      </div>
    </div>
  );
};

export default TrendingSearches;