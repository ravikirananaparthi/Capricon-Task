import React from 'react';
import { IoSearch } from "react-icons/io5";

const Search = () => {
  return (
    <div className="flex flex-row">
      <div className="bg-white rounded-full flex ml-2 mt-3 items-center md:w-[180px] lg:w-[330px] w-max-full">
        <input
          type="search"
          placeholder="Search"
          className="w-full py-2 px-3 bg-transparent cursor-pointer focus:outline-none text-black"
        />
        <IoSearch size={25} className="cursor-pointer text-black" />
      </div>
    </div>
  );
};

export default Search;