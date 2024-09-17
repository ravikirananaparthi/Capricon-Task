import React, { useContext, useState } from "react";
import { Link, Navigate } from "react-router-dom";
import { FaUser } from "react-icons/fa";
import { RxCross1 } from "react-icons/rx";
import axios from "axios";
import toast from "react-hot-toast";
import { Context, auth } from "../main";
import { GoogleAuthProvider, signInWithPopup } from "firebase/auth";
import { server } from "../main";
import l from '../assets/ggg.png';
function Googleregister() {
  const [programmingExperience, setProgrammingExperience] = useState("");
  const [learnedTechnologies, setLearnedTechnologies] = useState([]);
  const [newTechnology, setNewTechnology] = useState("");
  const { isAuthenticated, setAuth } = useContext(Context);
  const programmingExperienceOptions = [
    "0 years",
    "1 year",
    "2 years",
    "3 years",
    "4+ years",
  ];

  const handleProgrammingExperienceChange = (event) => {
    setProgrammingExperience(event.target.value);
  };

  const handleLearnedTechnologiesChange = (event) => {
    setNewTechnology(event.target.value);
  };

  const handleAddTechnology = () => {
    if (newTechnology.trim() !== "") {
      setLearnedTechnologies([...learnedTechnologies, newTechnology]);
      setNewTechnology("");
    }
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    const provider = new GoogleAuthProvider();
    try {
      const result = await signInWithPopup(auth, provider);
      const user1 = result.user;
      // User successfully signed in
      const user = result.user;
      console.log(user);
      const response = await axios.post(
        `${server}users/new/google`,
        {
          name: user1.displayName,
          email: user1.email,
          password: "ravikiran456",
          image: user1.photoURL,
          programmingExperience,
          learnedTechnologies,
          token: await result.user.accessToken,
        }
      );
      if (response.data && response.data.tokeen) {
        localStorage.setItem('token', response.data.tokeen);
        axios.defaults.headers.common['Authorization'] = `Bearer ${response.data.tokeen}`;
        toast.success(response.data.message);
        setAuth(true);
      } else {
        toast.error(response.data.message);
        setAuth(false);
      }
      // Send the token and user information to your backend for authentication
    } catch (error) {
      // Handle errors (refer to Firebase documentation for error codes)
      console.error("Error during sign-in:", error);
      toast.error("Registration failed. Please try again.");
    }
  };

  const handleRemoveTechnology = (indexToRemove) => {
    setLearnedTechnologies((prevTechnologies) =>
      prevTechnologies.filter((_, index) => index !== indexToRemove)
    );
  };
  if (isAuthenticated) return <Navigate to={"/app/viewposts"} />;
  return (
    <div className="flex flex-col items-center justify-center h-screen bg-gradient-to-br from-ravi via-chakri to-jaya">
      <div className="p-8 bg-gray-50/5 w-[22rem] md:w-[30rem] w-max-full max-w-md text-white inset-0 border-2 border-gradient  shadow-puk shadow-inner">
        <FaUser size={50} className="bg-sul rounded-full p-1 mx-auto mb-1" />
        <h2 className="text-2xl font-bold text-center mb-4 text-slate-50">
          Google Registration
        </h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <label className="block text-white">
              Programming Experience:
              <select
                value={programmingExperience}
                onChange={handleProgrammingExperienceChange}
                className="block w-full mt-1 p-2 border text-black bg-gradient-to-r from-puk to-slate-400 focus:outline-none placeholder-black focus:bg-puk/80"
              >
                <option value="">Select</option>
                {programmingExperienceOptions.map((option, index) => (
                  <option key={index} value={option}>
                    {option}
                  </option>
                ))}
              </select>
            </label>

            <label className="block text-white">
              Learned Technologies:
              <div className="flex items-center">
                <input
                  type="text"
                  value={newTechnology}
                  onChange={handleLearnedTechnologiesChange}
                  placeholder="Enter Learned Technologies"
                  className="w-full mt-1 p-2 text-black bg-gradient-to-r from-puk to-slate-400 focus:outline-none placeholder-black border border-transparent focus:border-gradient focus:border-2"
                />
                <button
                  type="button"
                  onClick={handleAddTechnology}
                  className="ml-2 px-4 py-2 mt-1 bg-blue-500 text-white rounded hover:bg-blue-600"
                >
                  Add
                </button>
              </div>
              <ul className="mt-2 flex flex-wrap">
                {learnedTechnologies.map((tech, index) => (
                  <li
                    key={index}
                    className="text-white flex items-center mr-2 mb-2 bg-gray-500 rounded-full px-3 py-1"
                  >
                    <span>{tech}</span>
                    <button
                      onClick={() => handleRemoveTechnology(index)}
                      className="ml-1 focus:outline-none"
                    >
                      <RxCross1 size={20} />
                    </button>
                  </li>
                ))}
              </ul>
            </label>
          </div>
          <button className="mx-auto mt-4 flex justify-center" type="submit">
            <div className="border-2 bg-gradient-to-r from-puk to-indigo-300 border-gray-700 font-semibold px-5 py-2 rounded-full flex items-center justify-center hover:bg-gradient-to-br hover:from-indigo-400 hover:to-cyan-400 transition duration-300 ease-in-out">
              <img
                className="h-7 w-7 rounded-full  mr-2"
                src={l}
                alt=""
              />
              <span className="text-gray-700">Sign up with Google</span>
            </div>
          </button>
          <p className="text-center mt-2">
            <p className="">Already have an Account ?</p>
            <Link to="/app/login" className="text-e p-1 underline ">
              Login
            </Link>
          </p>
        </form>
      </div>
      <div className="h-20 md:h-0"></div>
    </div>
  );
}

export default Googleregister;
