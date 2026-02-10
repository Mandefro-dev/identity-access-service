import express from "express";

const adminRouter = express.Router();
import { getAllUsers, deleteUser } from "../controllers/admin.controller.js";

import { verifyAccessToken } from "../middleware/verifyAccessToken.js";
import {
  alllowOwnerOrAdmin,
  restrictTo,
} from "../middleware/auth.middleware.js";

adminRouter.get("/users", verifyAccessToken, restrictTo("admin"), getAllUsers);

adminRouter.delete(
  "/user/:id",
  restrictTo("admin", "moderator"),
  alllowOwnerOrAdmin,
  deleteUser,
);

export default adminRouter;
