import jwt from "jsonwebtoken";
import crypto from "crypto";
import argon2 from "argon2";
import { RefreshToken } from "../backend/models/refreshToken.model";

export const signAccessToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_ACCESS_SECRET, {
    expiresIn: "15m",
  });
};

export const signRefreshToken = async (userId) => {
  const refreshToken = jwt.sign({ userId }, process.env.JWT_REFRESH_TOKEN, {
    expiresIn: "7d",
  });

  const hashed = await argon2.hash(refreshToken);
  await RefreshToken.create({
    userId,
    token: hashed,
    expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7),
  });

  return refreshToken;
};
