import express from "express";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import { connectDB } from "./db/connectDB.js";
import authRoutes from "./routes/auth.route.js";
import adminRoutes from "./routes/admin.routes.js";
import postRoutes from "./routes/post.routes.js";

dotenv.config();

const app = express();

const PORT = process.env.PORT || 5000;

app.use(express.json());
app.use(cookieParser());

app.get("/", (req, res) => {
  return res.send("Hello world");
});
app.use("/api/auth", authRoutes);
app.use("api/admin", adminRoutes);
app.use("api/post", postRoutes);

app.listen(PORT, () => {
  connectDB();
  console.log(`Server is running on port ${PORT} `);
});
