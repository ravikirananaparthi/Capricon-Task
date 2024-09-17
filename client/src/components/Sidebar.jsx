import React from 'react';
import { Link } from "react-router-dom";

import TrendingSearches from './TrendingSearches';
import SearchHistory from './SearchHistory';
import Search from './Search';

const Sidebar = () => {
  return (
    <div className="md:left md:overflow-y-auto md:w-1/4 m-1 md:my-auto">
      <div className="h-auto md:h-[5in] lg:max-h-[5in] flex flex-col items-center backdrop-blur-lg bg-gray-700 rounded-xl sm:sticky mt-20 md:mt-16">
        <Search />
        <div className="flex w-full justify-between">
          <TrendingSearches />
          <div className="border-r border-gray-600"></div>
          <SearchHistory />
        </div>
        <footer className="mt-auto mb-9 flex justify-center">
          <Link to="/app/createposts">
            <button className="py-2 px-10 md:px-16 lg:px-36 font-bold text-white bg-blue-500 rounded-lg hover:bg-blue-700 transition duration-300 ease-in-out focus:outline-none">
              + Post
            </button>
          </Link>
        </footer>
      </div>
    </div>
  );
};

export default Sidebar;