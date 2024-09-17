import React, { useContext, useState } from "react";
import { Link } from "react-router-dom";
import { FaUserCircle } from "react-icons/fa";
import { IoMenu } from "react-icons/io5";
import { RxCross1 } from "react-icons/rx";
import { Context, server } from "../main";
import toast from "react-hot-toast";
import axios from "axios";

const Nav = () => {
  const { user, isAuthenticated, setAuth, loader, setLoader } =
    useContext(Context);
  const [isOpen, setIsOpen] = useState(false);

  const toggleMenu = () => {
    setIsOpen(!isOpen);
  };

  const closeMenu = () => {
    setIsOpen(false);
  };

  const logOutHandler = async () => {
    setLoader(true);
    try {
      await axios.get(`${server}users/logout`, { withCredentials: true });
      toast.success("Logged Out Successfully");
      setAuth(false);
      localStorage.removeItem("token");
      axios.defaults.headers.common["Authorization"] = "";
      setLoader(false);
    } catch (error) {
      toast.error("Something went wrong.");
      setLoader(false);
    }
  };

  return (
    <nav className="bg-gradient-to-r from-guv/60 to-jagaur/90 text-white shadow-lg">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center">
            <Link to="/app/viewposts">
              <span className="font-bold text-3xl tracking-tight text-white">
                DevFinds
              </span>
            </Link>
            <div className="hidden md:block">
              <div className="ml-10 flex items-baseline space-x-4">
                <Link
                  to="/app/viewposts"
                  className="px-3 py-2 rounded-md text-sm font-medium hover:bg-[#57739F] transition duration-150 ease-in-out"
                  onClick={closeMenu}
                >
                  Home
                </Link>
                <Link
                  to="/app/createposts"
                  className="px-3 py-2 rounded-md text-sm font-medium hover:bg-[#57739F] transition duration-150 ease-in-out"
                  onClick={closeMenu}
                >
                  CreatePosts
                </Link>

                {/* Conditionally render dashboard link based on user role */}
                {user?.role === "admin" ? (
                  <Link
                    to="/app/admin/dashboard"
                    className="px-3 py-2 rounded-md text-sm font-medium hover:bg-[#57739F] transition duration-150 ease-in-out"
                    onClick={closeMenu}
                  >
                    Admin Dashboard
                  </Link>
                ) : user?.role === "user" ? (
                  <Link
                    to="/app/user/dashboard"
                    className="px-3 py-2 rounded-md text-sm font-medium hover:bg-[#57739F] transition duration-150 ease-in-out"
                    onClick={closeMenu}
                  >
                    My Dashboard
                  </Link>
                ) : null}

                <button
                  onClick={() => {
                    logOutHandler();
                    closeMenu();
                  }}
                  className="px-3 py-2 rounded-md text-sm font-medium hover:bg-red-500 transition duration-150 ease-in-out"
                >
                  Logout
                </button>
              </div>
            </div>
          </div>

          <div className="hidden md:block">
            <div className="ml-4 flex items-center md:ml-6">
              {isAuthenticated && (
                <Link to="/app/profile" className="flex-shrink-0">
                  {user.image ? (
                    <img
                      src={user.image}
                      alt="User"
                      className="h-8 w-8 rounded-full object-cover"
                    />
                  ) : (
                    <FaUserCircle size={30} />
                  )}
                </Link>
              )}
            </div>
          </div>

          <div className="flex md:hidden">
            <button
              onClick={toggleMenu}
              className="inline-flex items-center justify-center p-2 rounded-md hover:bg-[#57739F] focus:outline-none focus:ring-2 focus:ring-inset focus:ring-white transition duration-150 ease-in-out"
            >
              <span className="sr-only">Open main menu</span>
              {isOpen ? <RxCross1 size={20} /> : <IoMenu size={20} />}
            </button>
          </div>
        </div>
      </div>

      {isOpen && (
        <div className="md:hidden">
          <div className="px-2 pt-2 pb-3 space-y-1 sm:px-3">
            <Link
              to="/app/viewposts"
              className="block px-3 py-2 rounded-md text-base font-medium hover:bg-[#57739F] transition duration-150 ease-in-out"
              onClick={closeMenu}
            >
              Home
            </Link>
            <Link
              to="/app/createposts"
              className="block px-3 py-2 rounded-md text-base font-medium hover:bg-[#57739F] transition duration-150 ease-in-out"
              onClick={closeMenu}
            >
              CreatePosts
            </Link>

            {/* Conditionally render dashboard link based on user role */}
            {user?.role === "admin" ? (
              <Link
                to="/app/admin/dashboard"
                className="block px-3 py-2 rounded-md text-base font-medium hover:bg-[#57739F] transition duration-150 ease-in-out"
                onClick={closeMenu}
              >
                Admin Dashboard
              </Link>
            ) : user?.role === "user" ? (
              <Link
                to="/app/user/dashboard"
                className="block px-3 py-2 rounded-md text-base font-medium hover:bg-[#57739F] transition duration-150 ease-in-out"
                onClick={closeMenu}
              >
                My Dashboard
              </Link>
            ) : null}

            <button
              onClick={() => {
                logOutHandler();
                closeMenu();
              }}
              className="block px-3 py-2 rounded-md text-base font-medium hover:bg-red-500 transition duration-150 ease-in-out"
            >
              Logout
            </button>
          </div>
        </div>
      )}
    </nav>
  );
};

export default Nav;
