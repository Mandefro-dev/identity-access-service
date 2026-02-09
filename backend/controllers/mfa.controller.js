// import { generateSecret, generateURI, verify } from "otplib";
import { generateSecret, generateURI, verify, generate } from "otplib";

import qrcode from "qrcode";
import { User } from "../models/user.model.js";
import crypto from "crypto";
import argon2 from "argon2";
import jwt from "jsonwebtoken";
import { signAccessToken, signRefreshToken } from "../../utils/token.js";
// const { authenticator } = otplib;
//generte a secret and QRcode

export const generateMfaSecret = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    const secret = generateSecret();

    const otpauth = generateURI({
      issuer: "auth",
      label: user.email,

      secret,
    });

    const imageUri = await qrcode.toDataURL(otpauth);
    user.mfaSecret = secret;
    await user.save();

    res.status(200).json({
      success: true,
      secret,
      qrCode: imageUri,
    });
  } catch (error) {
    console.error("error in Setuping", error);
    res.status(500).json({
      message: error.message,
    });
  }
};

export const enableMfa = async (req, res) => {
  try {
    const { code } = req.body;
    const user = await User.findById(req.userId);

    const isValid = verify({
      token: code,
      secret: user.mfaSecret,
      window: 1,
    });

    if (!isValid) {
      return res.status(400).json({
        success: false,
        message: "Invalid code",
      });
    }

    const backupCodes = Array.from({ length: 5 }, () =>
      crypto.randomBytes(4).toString("hex"),
    );

    const hashedBackupCodes = await Promise.all(
      backupCodes.map(async (code) => {
        return {
          code: await argon2.hash(code),
          used: false,
        };
      }),
    );

    user.isMfaEnabled = true;
    user.backupCodes = hashedBackupCodes;
    await user.save();

    res.status(200).json({
      success: true,
      message: "MFA Enabled succesfully ",
      backupCodes,
    });
  } catch (error) {
    res.status(500).json({
      message: error.message,
    });
  }
};

export const verifyMfaLogin = async (req, res) => {
  try {
    const { code, mfaToken } = req.body;
    if (!mfaToken)
      return res.status(401).json({
        message: "No MFA token provided.",
      });

    let decoded;
    try {
      decoded = jwt.verify(mfaToken, process.env.JWT_ACCESS_SECRET);
    } catch (error) {
      return res.status(401).json({
        message: "MFA session expired,Login Again.",
      });
    }

    const user = await User.findById(decoded.userId);
    if (!user)
      return res.status(401).json({
        message: "User not found.",
      });

    let isValid = verify({ token: code, secret: user.mfaSecret });

    if (!isValid) {
      const backupCodeDoc = user.backupCodes.find((bc) => !bc.used);

      for (const record of user.backupCodes) {
        if (!record.used) {
          const isMatch = await argon2.verify(record.code, code);
          if (isMatch) {
            isValid = true;
            record.used = true;
            user.markModified("backupCodes");
            await user.save();
            break;
          }
        }
      }
    }

    if (!isValid) {
      return res.status(401).json({
        success: false,
        message: "Invalid code.",
      });
    }

    const accessToken = signAccessToken(user._id);
    const refreshToken = await signRefreshToken(user._id, req);
    res.cookie("refreshToken", refreshToken, {
      //options
    });

    res.status(200).json({
      success: true,
      accessToken,
      user: { _id: user._id, email: user.email },
    });
  } catch (error) {
    res.status(500).json({
      message: error.message,
    });
  }
};
