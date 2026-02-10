import express from "express";

const adminRouter = express.Router();
import { getAllUsers, deleteUser } from "../controllers/admin.controller";

import { verifyAccessToken } from "../middleware/verifyAccessToken";
import { alllowOwnerOrAdmin, restrictTo } from "../middleware/auth.middleware";

router.get("/users", verifyAccessToken, restrictTo("admin"), getAllUsers);

router.delete(
  "/user/:id",
  restrictTo("admin", "moderator"),
  alllowOwnerOrAdmin,
  deleteUser,
);

export default adminRouter;
