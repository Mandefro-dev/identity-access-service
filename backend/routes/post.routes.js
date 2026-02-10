import express from "express";
import { Post } from "../models/post.model.js";
import { verifyAccessToken } from "../middleware/verifyAccessToken.js";
import {
  canModifyResource,
  enviromentGuard,
} from "../middleware/abac.middleware.js";

const postRouter = express.Router();

postRouter.delete(
  "/:id",
  verifyAccessToken,
  enviromentGuard,
  canModifyResource(Post),
  async (req, res) => {
    await req.resource.deleteOne();
    res.json({
      success: true,
      message: "Post deleted",
    });
  },
);

export default postRouter;
