import express from "express";
import {
  signup,
  login,
  logout,
  verifyEmail,
  forgotPassword,
  resetPassword,
  checkAuth,
  refreshToken,
} from "../controllers/auth.controller.js";
import { verifyAccessToken } from "../middleware/verifyAccessToken.js";

const router = express.Router();
router.get("/check-auth", verifyAccessToken, checkAuth);
router.post("/signup", signup);
router.post("/login", login);
router.post("/logout", logout);
router.post("/verify-email", verifyEmail);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password/:token", resetPassword);
router.post("/refresh", refreshToken);
export default router;
