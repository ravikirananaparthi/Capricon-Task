import express from "express";
import { Server } from "socket.io";
import userRouter from "./routes/user.js";
import postRouter from "./routes/post.js";
import { config } from "dotenv";
import cookieParser from "cookie-parser";
import { errorMiddleWare } from "./middlewares/errorHandling.js";
import cors from "cors";
import { createServer } from "http";
import { User } from "./models/user.js";
import * as fs from 'fs';
import helmet from "helmet";
import morgan from "morgan";
import jwt from "jsonwebtoken";

import admin from "firebase-admin";
import { getAuth } from "firebase-admin/auth";

const serviceAccountKey = JSON.parse(fs.readFileSync('./capricontechnology-c23f1-firebase-adminsdk-p3p26-65facadc51.json'));

export const app = express();
export const server = new createServer(app);
try {
  config({ path: "./data/config.env" });
  console.log("Environment variables loaded from config.env");
} catch (error) {
  console.error("Error loading environment variables:", error);
}
const frontendOrigin = ["http://localhost:5173",'https://capricon-task.vercel.app/'];


export const io = new Server(server, {
  cors: {
    origin: frontendOrigin,
    methods: ["GET", "POST"],
    credentials: true,
  },
});

//using middleware
app.use(helmet());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan("dev"));
app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    origin: frontendOrigin,
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);

//using Routes
app.use("/api/v1/users", userRouter);
app.use("/api/v1/posts", postRouter);


app.get("/", (req, res) => {
  res.send("working");
});

admin.initializeApp({
  credential: admin.credential.cert(serviceAccountKey),
});


app.use(errorMiddleWare);
