import React from 'react';
import { CiClock1 } from "react-icons/ci";

const SearchHistory = () => {
  // You can add state or props to manage the actual search history
  return (
    <div className="w-[15rem]">
      <div className="p-4 text-white">
        <div className="flex flex-row">
          <CiClock1 size={25} className="mr-2 text-green-500" />
          <p className="text-sm md:text-base text-white">History</p>
        </div>
        {/* Add Search History items here */}
      </div>
    </div>
  );
};

export default SearchHistory;