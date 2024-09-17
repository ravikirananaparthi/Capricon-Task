import { Route, BrowserRouter as Router, Routes } from "react-router-dom";
import Login from "./pages/Login";
import Register from "./pages/Register";
import { Toaster } from "react-hot-toast";
import { useContext, useEffect, useState } from "react";
import axios from "axios";
import { Context, server } from "./main";
import { io } from "socket.io-client";
import Googleregister from "./pages/Googleregister";
import Landing from "./pages/Landing";
//import Navbar from "./components/Navbar.jsx";
import CreatePosts from "./pages/CreatePosts.jsx";
import AdminDashboard from "./pages/AdminDashboard.jsx";
import UserDashboard from "./pages/UserDashboard.jsx";
import Feed from "./pages/Feed.jsx";
import Nav from "./components/Nav.jsx";





const ser =import.meta.env.SER;

function App(props) {
  const { isAuthenticated, setUser, setAuth, setLoader, setfetch, isAdmin, setIsAdmin } =
    useContext(Context);
  

  const toggleTheme = () => {
    setDarkMode(!darkMode);
  };
  useEffect(() => {
    setLoader(true);
    axios
      .get(`${server}users/me`, {
        withCredentials: true,
      })
      .then((res) => {
        setUser(res.data.user);
        console.log(res.data);
        setIsAdmin(res.data.user.role === "admin");
        setAuth(true);
        setLoader(false);
      })
      .catch((error) => {
        setUser({});
        setAuth(false);
        setIsAdmin(false);
        setLoader(false);
      });
  }, [isAuthenticated]);

  console.log(isAuthenticated)
  const token = localStorage.getItem('token') 
  if (token) {
    axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  }
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/app/*" element={<ProtectedRoutes />} />
      </Routes>
    </Router>
  );
}

function ProtectedRoutes() {
  return (
    <>
      <Nav />
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/createposts" element={<CreatePosts />} />
        <Route path="/viewposts" element={<Feed />} />

        <Route path="/register/google" element={<Googleregister />} />


          <Route path="/admin/dashboard" element={<AdminDashboard />} />
      
          <Route path="/user/dashboard" element={<UserDashboard />} />

      </Routes>

      <Toaster />
    </>
  );
}
/*        <Route path="/hi" element={<TrendingPosts/>} />
        <Route path='/trending' element={<Trending/>}/>
        <Route path="/viewposts" element={<Feed />} />
        <Route path="/posts/:postId" element={<PostDetail />} />
        <Route path="/userprofile/:userid" element={<Userprofile />} />
        <Route path="/message" element={<Dm />} />
         */
export default App;
