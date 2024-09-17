import React, { useContext, useState } from "react";
import { Link, Navigate } from "react-router-dom";
import axios from "axios";
import toast from "react-hot-toast";
import { FaUser } from "react-icons/fa";
import { Context, auth, googleProvider } from "../main";
import { RxCross1 } from "react-icons/rx";
import { signInWithPopup } from "firebase/auth";
import { server } from "../main";
import l from '../assets/ggg.png';
function Registration() {
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [programmingExperience, setProgrammingExperience] = useState("");
  const [learnedTechnologies, setLearnedTechnologies] = useState([]);
  const [newTechnology, setNewTechnology] = useState("");
  const [showGoogleRegister, setShowGoogleRegister] = useState(false);
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

  const handleFullNameChange = (event) => {
    setFullName(event.target.value);
  };

  const handleEmailChange = (event) => {
    setEmail(event.target.value.trim());
  };

  const handlePasswordChange = (event) => {
    setPassword(event.target.value.trim());
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    console.log(programmingExperience);
    try {
      const response = await axios.post(
        `${server}users/new`,
        {
          name: fullName,
          email,
          password,
          image:null,
          programmingExperience,
          learnedTechnologies,
        },
        {
          headers: {
            "Content-Type": "application/json",
          },
          withCredentials: true,
        }
      );

      if (response.data) {
        toast.success(response.data.message);
        setAuth(true);
      } else {
        toast.error("Registration failed. Please try again.");
        setAuth(false);
      }
    } catch (error) {
      console.error(error); // Log the error object
      toast.error("Registration failed. Please try again.");
      setAuth(false);
    }
  };

  const handleRemoveTechnology = (indexToRemove) => {
    setLearnedTechnologies((prevTechnologies) => {
      // Create a new array excluding the technology at the specified index
      const updatedTechnologies = prevTechnologies.filter(
        (_, index) => index !== indexToRemove
      );
      return updatedTechnologies;
    });
  };

  const handleClickgo = () => {
    setShowGoogleRegister(true);
  };

  console.log(programmingExperience, learnedTechnologies);
  if (isAuthenticated) return <Navigate to={"/app/viewposts"} />;

  return (
    <div className="flex flex-col items-center justify-center h-screen overflow-y-auto bg-gradient-to-br from-ravi via-chakri to-jaya">
      <div className="p-8 py-3 bg-gray-50/5 w-[22rem] md:w-[30rem] w-max-full max-w-md text-white inset-0 border-2 border-gradient  shadow-puk shadow-inner mt-16">
        <FaUser size={50} className="bg-sul rounded-full p-1 mx-auto"/>
        <h2 className="text-2xl font-bold text-center mb-4">Registration</h2>
        <form onSubmit={handleSubmit} className="space-y-1">
          <div className="space-y-1">
            <label className="block text-white">
              Full Name:
              <input
                type="text"
                value={fullName}
                onChange={handleFullNameChange}
                placeholder="Enter Full Name"
                className="w-full p-1.5 border border-gray-300 rounded  text-black bg-gradient-to-r from-puk to-slate-400 focus:outline-none focus:border-gray-500 placeholder-black "
              />
            </label>
            <label className="block text-white">
              Email:
              <input
                type="text"
                value={email}
                onChange={handleEmailChange}
                placeholder="Enter Email"
                className="w-full p-1.5 border border-gray-300 rounded text-black bg-gradient-to-r from-puk to-slate-400 focus:outline-none focus:border-gray-500 placeholder-black "
              />
            </label>
            <label className="block text-white">
              Set Password:
              <input
                type="password"
                value={password}
                onChange={handlePasswordChange}
                placeholder="Enter Password"
                className="w-full p-1.5 border border-gray-300 rounded text-black bg-gradient-to-r from-puk to-slate-400 focus:outline-none focus:border-gray-500 placeholder-black "
              />
            </label>
          </div>
          <div className="space-y-1">
            <label className="block text-white">
              Programming Experience:
              <select
                value={programmingExperience}
                onChange={handleProgrammingExperienceChange}
                className="block w-full p-1.5 border border-gray-300 rounded text-black bg-gradient-to-r from-puk to-slate-400 focus:outline-none focus:border-gray-500 placeholder-black "
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
                  className="w-full p-1.5 border border-gray-300 rounded text-black bg-gradient-to-r from-puk to-slate-400 focus:outline-none focus:border-gray-500 placeholder-black "
                />
                <button
                  type="button"
                  onClick={handleAddTechnology}
                  className="ml-2 px-4 py-1 bg-blue-500 text-white rounded hover:bg-blue-600"
                >
                  Add
                </button>
              </div>
              <ul className="mt-2 mb-2 flex flex-wrap">
                {learnedTechnologies.map((tech, index) => (
                  <li
                    key={index}
                    className="text-white flex items-center mr-2 mb-1 bg-gray-500 rounded-full px-3 py-1"
                  >
                    <span>{tech}</span>
                    <button
                      onClick={() => handleRemoveTechnology(index)}
                      className="ml-1 focus:outline-none"
                    >
                      <RxCross1 size={12} />
                    </button>
                  </li>
                ))}
              </ul>
            </label>
          </div>
          <button
            type="submit"
            className="bg-gradient-to-r from-puk to-indigo-300 font-semibold hover:bg-gradient-to-br hover:from-indigo-400 hover:to-cyan-400 text-black rounded-lg p-2  w-full"
          >
            Register
          </button>
          <Link to={'/app/register/google'}>
        <button className="mx-auto mt-4 flex justify-center" onClick={handleClickgo}>
          <div className=" border-2 bg-gradient-to-r from-puk to-indigo-300 border-gray-700 font-semibold px-5 py-2 rounded-full flex items-center justify-center hover:bg-gradient-to-br hover:from-indigo-400 hover:to-cyan-400 transition duration-300 ease-in-out">
            <img
              className="h-7 w-7 rounded-full mr-2"
              src={l}
              alt=""
            />
            <span className="text-black ml-2">Sign up with Google</span>
          </div>
        </button>
        </Link>
          <p className="text-center">
            <p className="text-blue-400">Have an Account ?</p>
            <Link to="/app/login" className="text-e r p-1 underline">
              or Login
            </Link>
          </p>
        </form>
      </div>
      <div className="h-20 md:h-0"></div>
    </div>
  );
}

export default Registration;
