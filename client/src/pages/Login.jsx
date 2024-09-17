import React, { useContext, useState } from "react";
import { Link, Navigate } from "react-router-dom";
import { Context, auth, server } from "../main";
import toast from "react-hot-toast";
import axios from "axios";
import { GoogleAuthProvider, signInWithPopup } from "firebase/auth";
import l from '../assets/ggg.png';
import "../index.css";

function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false); // Add loading state

  const { isAuthenticated, setAuth } = useContext(Context);

  const handleEmailChange = (event) => {
    setEmail(event.target.value);
  };

  const handlePasswordChange = (event) => {
    setPassword(event.target.value);
  };

  const togglePasswordVisibility = () => {
    setShowPassword(!showPassword);
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setLoading(true); // Set loading state to true

    try {
      const { data } = await axios.post(
        `${server}users/login`,
        {
          email,
          password,
        },
        {
          headers: {
            "Content-Type": "application/json",
          },
          withCredentials: true,
        }
      );
      toast.success(data.message);
      setAuth(true);
    } catch (error) {
      toast.error(error.response.data.message);
      setAuth(false);
    }

    setLoading(false); // Set loading state back to false after request
  };

  const handleClickGoogleSignIn = async (event) => {
    event.preventDefault();

    try {
      const provider = new GoogleAuthProvider();
      const result = await signInWithPopup(auth, provider);
      const user = result.user;

      const response = await axios.post(`${server}users/google-login`, {
        token: user.accessToken,
      });

      if (response.data.success) {
        localStorage.setItem('token', response.data.token);
        axios.defaults.headers.common['Authorization'] = `Bearer ${response.data.token}`;
        toast.success(response.data.message);
        setAuth(true);
      } else {
        toast.error(response.data.error);
        setAuth(false);
      }
    } catch (error) {
      console.error('Error during Google sign-in:', error);
      toast.error('Login failed. Please try again.');
    }
  };

  if (isAuthenticated) return <Navigate to={"/app/viewposts"} />;

  return (
    <div className=" flex justify-center items-center h-screen bg-gradient-to-br from-ravi via-chakri to-jaya">
      <div className="p-8 bg-gray-50/5 w-[22rem] md:w-[30rem] w-max-full max-w-md text-white inset-0 border-2 border-gradient  shadow-puk shadow-inner ">
        <h2 className="text-center text-2xl font-bold mb-4">Login</h2>
        <form onSubmit={handleSubmit} className="">
          <div>
            <label className="block">
              Email:
              <input
                type="text"
                value={email}
                onChange={handleEmailChange}
                placeholder="Enter Email"
                className="block mt-1 p-2 w-full rounded text-black bg-gradient-to-r from-puk to-slate-400 focus:outline-none placeholder-black border border-transparent focus:border-gradient focus:border-2"
              />
            </label>
          </div>
          <div className="mt-2">
            <label className="block">
              Password:
              <input
                type="password"
                value={password}
                onChange={handlePasswordChange}
                placeholder="Enter Password"
                className="block mt-1 p-2 w-full border border-gray-300 rounded text-black bg-gradient-to-r from-puk to-slate-400 focus:outline-none focus:border-gray-500 placeholder-black "
              />
            </label>
          </div>
          <div className="mt-8">
          <button
            type="submit"
            className="bg-gradient-to-r from-puk to-indigo-300 font-semibold hover:bg-gradient-to-br hover:from-indigo-400 hover:to-cyan-400 text-black rounded-lg p-2  w-full "
            disabled={loading} // Disable button when loading
          >
            {loading ? ( // Conditionally render spinner if loading
              <div role="status">
                <svg
                  aria-hidden="true"
                  className="w-6 h-6 animate-spin mr-3"
                  viewBox="0 0 24 24"
                >
                  <path
                    fill="none"
                    d="M0 0h24v24H0z"
                  />
                  <path
                    fill="currentColor"
                    d="M12 2C6.486 2 2 6.486 2 12s4.486 10 10 10 10-4.486 10-10S17.514 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13h2v6h-2zm0 8h2v2h-2z"
                  />
                </svg>
                <span>Loading...</span>
              </div>
            ) : (
              "Login"
            )}
          </button>
          </div>
          <button className="mx-auto mt-4 flex justify-center" onClick={handleClickGoogleSignIn}>
            <div className="border-2 bg-gradient-to-r from-puk to-indigo-300 border-gray-700 font-semibold px-5 py-2 rounded-full flex items-center justify-center hover:bg-gradient-to-br hover:from-indigo-400 hover:to-cyan-400 transition duration-300 ease-in-out">
              <img
                className="h-7 w-7 rounded-full mr-2"
                src={l}
                alt=""
              />
              <span className="text-black">Sign In with Google</span>
            </div>
          </button>
        </form>
        <div class="flex items-center justify-between mt-3">
            <div class="w-[4rem] md:w-[7rem] border-t border-gray-400"></div>
            <div class="px-2 ">new to DevFinds</div>
            <div class="w-[4rem] md:w-[7rem] border-t border-gray-400"></div>
        </div>
        <p className="text-white"> Create Account ?</p>
        <div className="flex flex-row justify-between text-center mt-2">
          <p>
            <Link to="/app/register" className="text-e  p-1 underline">
               Sign Up
            </Link>
          </p>
          <p>or</p>
          <Link  to='/app/register/google'>
            <span className="underline text-e  p-1">Google Registration -- </span>
          </Link>
        </div>
      </div>
    </div>
  );
}

export default Login;
