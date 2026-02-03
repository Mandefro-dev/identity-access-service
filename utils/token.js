import jwt from "jsonwebtoken";
import crypto from "crypto";

import { RefreshToken } from "../backend/models/refreshToken.model";

export const signAccessToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_ACCESS_SECRET, {
    expiresIn: "15m",
  });
};

export const signRefreshToken = async (userId) => {
  const token = crypto.randomBytes(40).toString("hex");
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  await RefreshToken.create({
    userId,
    token: tokenHash,
    expiresAt,
  });

  return token;
};
