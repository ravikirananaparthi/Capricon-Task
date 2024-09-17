import { useContext, useState } from "react";
import {
  getStorage,
  ref,
  uploadBytesResumable,
  getDownloadURL,
} from "firebase/storage";
import { Context, app, server } from "../main";
import axios from "axios";
import LinearProgress from "@mui/material/LinearProgress";
import { Button, Card, CardContent } from "@mui/material";
import { IoCaretBackCircleSharp } from "react-icons/io5";
import { Link } from "react-router-dom";
import { toast } from "react-hot-toast";
import "../index.css";

function CreatePosts() {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [imgurl, setImgUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [previewImage, setPreviewImage] = useState(null);
  const { isAuthenticated } = useContext(Context);

  // Handle image upload separately
  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onloadend = () => {
        setPreviewImage(reader.result);
      };
      reader.readAsDataURL(file);

      const storage = getStorage(app);
      const storageRef = ref(storage, file.name);
      const uploadTask = uploadBytesResumable(storageRef, file);

      uploadTask.on(
        "state_changed",
        (snapshot) => {
          const progress = Math.round(
            (snapshot.bytesTransferred / snapshot.totalBytes) * 100
          );
          setUploadProgress(progress);
        },
        (error) => {
          console.error("Error uploading file:", error);
        },
        () => {
          getDownloadURL(uploadTask.snapshot.ref).then((downloadURL) => {
            setImgUrl(downloadURL);
            console.log("File available at", downloadURL);
          });
        }
      );
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!title || !description) {
      toast.error("Title and Description are mandatory!");
      return;
    }
    try {
      setLoading(true);

      const { data } = await axios.post(
        `${server}users/posts`,
        { title, description, image: imgurl, tof: "pic" }, // Only "pic" is allowed
        {
          withCredentials: true,
        }
      );

      if (data.success === true) {
        toast.success("This posting is sent for admin approval!");
        setTitle("");
        setDescription("");
        setPreviewImage(null);
        setImgUrl("");
        setLoading(false);
        setUploadProgress(0);
      }
    } catch (error) {
      console.error("Error creating post:", error);
      setLoading(false);
      toast.error("Failed to create post");
    }
  };

  return (
    <div className="flex justify-center items-center h-screen area">
      <ul class="circles">
        <li></li>
        <li></li>
        <li></li>
        <li></li>
        <li></li>
        <li></li>
        <li></li>
        <li></li>
        <li></li>
        <li></li>
      </ul>
      <div className="absolute top-0 left-0 right-0 flex justify-between items-center px-8 pt-24 cursor-pointer">
        <Link to={"/app/viewposts"}>
          <div className="flex items-center">
            <IoCaretBackCircleSharp
              className="text-blue-500 text-3xl cursor-pointer mr-2"
            />
            <h2 className="text-xl font-bold text-black hover:underline">
              Back to Feed
            </h2>
          </div>
        </Link>
      </div>
      <Card className="w-full lg:w-2/3 xl:w-1/2 p-8 shadow-lg rounded-lg mt-10 z-10">
        <CardContent>
          <h2 className="text-2xl font-bold text-center mb-6">
            Create a New Post
          </h2>
          <input
            type="text"
            placeholder="Title"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            fullWidth
            className="w-full px-4 py-2 mb-4 text-gray-800 border border-gray-300 rounded-md focus:outline-none focus:border-blue-500 bg-white"
          />
          <textarea
            placeholder="Description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            className="w-full h-40 px-4 py-2 mb-4 text-gray-800 border border-gray-300 rounded-md resize-none focus:outline-none focus:border-blue-500 bg-white"
          />
          <input
            type="file"
            accept="image/*"
            onChange={handleFileUpload}
            className="mb-4 mt-5"
          />
          {previewImage && (
            <img
              src={previewImage}
              alt="Preview"
              className="max-w-[70px] h-auto mb-4"
            />
          )}
          {uploadProgress > 0 && (
            <LinearProgress
              variant="determinate"
              value={uploadProgress}
              className="mb-4"
            />
          )}
          <Button
            onClick={handleSubmit}
            variant="contained"
            color="primary"
            disabled={loading || (uploadProgress > 0 && uploadProgress < 100)}
            fullWidth
          >
            {loading ? "Creating Post..." : "Create Post"}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

export default CreatePosts;
