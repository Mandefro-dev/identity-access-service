import jwt from "jsonwebtoken";
import crypto from "crypto";
import { getDeviceInfo } from "./deviceDetector.js";

import { RefreshToken } from "../backend/models/refreshToken.model.js";

export const signAccessToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_ACCESS_SECRET, {
    expiresIn: "15m",
  });
};

export const signRefreshToken = async (userId, req) => {
  const token = crypto.randomBytes(40).toString("hex");
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  const { ip, userAgent, os, browser, device } = getDeviceInfo(req);

  await RefreshToken.create({
    userId,
    token: tokenHash,
    expiresAt,
    ipAddress: ip,
    userAgent,
    deviceInfo: {
      os,
      browser,
      device,
    },
  });

  return token;
};
