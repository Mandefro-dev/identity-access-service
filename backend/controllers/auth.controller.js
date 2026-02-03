import { User } from "../models/user.model.js";

import crypto from "crypto";
import argon2 from "argon2";
import jwt from "jsonwebtoken";
import { generateVerficationToken } from "../../utils/generateVerificationToken.js";
import { generateTokenAndSetCookie } from "../../utils/generateTokenAndSetCookie.js";
import {
  sendverificationEmail,
  sendWelcomeEmail,
  sendPasswordResetEmail,
  sendPasswordResetSuccessEmail,
} from "../mailtrap/emails.js";
import {
  signupSchema,
  loginSchema,
  verifyEmailSchema,
} from "../../utils/validationSchemas.js";
import { signAccessToken, signRefreshToken } from "../../utils/token.js";
import { RefreshToken } from "../models/refreshToken.model.js";

export const refreshToken = async (req, res) => {
  const incomingToken = req.cookies.refreshToken;
  if (!incomingToken) {
    return res.status(401).json({ message: "No token provided" });
  }
  const tokenHash = crypto
    .createHash("sha256")
    .update(incomingToken)
    .digest("hex");
  const tokenDoc = await RefreshToken.findOne({ token: tokenHash });
  if (!tokenDoc) {
    res.clearCookie("refreshToken");
    return res.status(401).json({ message: "Invalid token" });
  }
  if (tokenDoc.revoked) {
    await RefreshToken.deleteMany({ userId: tokenDoc.userId });
    res.clearCookie("refreshToken");
    return res.status(403).json({
      message: "Security Alert: Token reuse Detected, All sessions revoked",
    });
  }

  if (new Date() > tokenDoc.expiresAt) {
    await RefreshToken.findByIdAndDelete(tokenDoc._id);
    res.clearCookie("refreshToken");
    res.status(401).json({ message: "Token expired" });
  }
  const newAccessToken = signAccessToken(tokenDoc.userId);
  const newRefreshTokenPlain = crypto.randomBytes(40).toString("hex");
  const newRefreshTokenHash = crypto
    .createHash("sha256")
    .update(newRefreshTokenPlain)
    .digest("hex");

  tokenDoc.revoked = true;
  tokenDoc.replaceByToken = newRefreshTokenHash;
  await tokenDoc.save();

  await RefreshToken.create({
    userId: tokenDoc.userId,
    token: newRefreshTokenHash,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  });
  res.cookie("refreshToken", newRefreshTokenPlain, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  res.status(200).json({ accessToken: newAccessToken });
};
export const signup = async (req, res) => {
  try {
    const { email, name, password } = signupSchema.parse(req.body);

    const userAlreadyExists = await User.findOne({ email });

    if (userAlreadyExists) {
      return res.status(400).json({
        success: false,
        message: "User already exists.",
      });
    }
    // const salt = bcrypt.genSalt(12);
    const hashedPassword = await argon2.hash(password);
    // const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = generateVerficationToken();

    const user = new User({
      email,
      password: hashedPassword,
      name,
      verificationToken,
      verificationTokenExpiresAt: Date.now() + 1000 * 60 * 60 * 24,
    });
    await user.save();

    //jwt
    // generateTokenAndSetCookie(res, user._id);
    const accessToken = signAccessToken(user._id);
    const refreshToken = await signRefreshToken(user._id);
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    });
    await sendverificationEmail(user.email, verificationToken);

    res.status(201).json({
      success: true,
      accessToken,
      message: "User create successfully.",
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    if (error.name === "ZodError") {
      return res.status(400).json({
        success: false,
        meesage: "Validation Error",
        errors: error.errors.map((e) => e.message),
      });
    }

    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

export const verifyEmail = async (req, res) => {
  try {
    const { code } = verifyEmailSchema.parse(req.body);
    const user = await User.findOne({
      verificationToken: code,
      verificationTokenExpiresAt: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired verification code",
      });
    }
    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpiresAt = undefined;
    await user.save();
    await sendWelcomeEmail(user.email, user.name);
    res.status(201).json({
      success: true,
      message: "Email sent succesfully.",
    });
  } catch (error) {
    if (error.name === "ZodError") {
      return res.status(400).json({
        success: false,
        message: "Validation error",
        errors: error.errors.map((e) => e.message),
      });
    }
    console.log("Error in verifying email", error);
    res.status(500).json({ success: false, message: "server error" });
  }
};
export const login = async (req, res) => {
  try {
    const { email, password } = loginSchema.parse(req.body);

    // if (!email || !password) {
    //   return res.status(400).json("All field are required.");
    // }
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({
        success: false,
        message: "user doesn't exist. please signin first",
      });
    }
    const isPasswordValid = await argon2.verify(user.password, password);
    if (!isPasswordValid) {
      return res.status(400).json({
        success: false,
        message: "Password doesn't match.",
      });
    }
    // generateTokenAndSetCookie(res, user._id);

    const accessToken = signAccessToken(user._id);
    const refreshToken = await signRefreshToken(user._id);
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    user.lastLogin = Date.now();
    await user.save();

    // await sendWelcomeEmail(user.email, user.name);
    return res.status(200).json({
      success: true,
      accessToken,
      message: "login successfull.",
      user: { ...user._doc, password: undefined },
    });
  } catch (error) {
    if (error.name === "ZodError") {
      return res.status(400).json({
        success: false,
        message: "validation error",
        errors: error.errors.map((e) => {
          e.message;
        }),
      });
    }
    console.error("Error wehn try to login", error);
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};
export const forgotPassword = async (req, res) => {
  try {
    const { email } = verifyEmailSchema.parse(req.body);

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "User is not found.",
      });
    }

    const resetToken = crypto.randomBytes(20).toString("hex");
    const resetTokenExpiresAt = Date.now() + 1000 * 60 * 60; //1hr
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpiresAt = resetTokenExpiresAt;
    await user.save();
    //send email
    const resetUrl = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;

    await sendPasswordResetEmail(user.email, resetUrl);
    return res.status(200).json({
      success: true,
      message: "Reset password sent to your successfully.",
    });
  } catch (error) {
    if (error.name === "ZodError") {
      return res.status(400).json({
        success: false,
        message: "validation error",
        errors: error.errors.map((e) => e.message),
      });
    }
    return res.status(400).json({
      success: false,
      message: error.message,
    });
  }
};
export const resetPassword = async (req, res) => {
  const { password } = req.body;
  const { token } = req.params;

  try {
    if (!password) {
      return res.status(400).json({
        success: false,
        message: "Enter  passwords first",
      });
    }
    // if (password !== repeatPassword) {
    //   return res.status(400).json({
    //     success: false,
    //     message: "Password doesn't match.",
    //   });
    // }
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpiresAt: { $gt: Date.now() },
    });
    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid and expired reset token.",
      });
    }

    const hashedPassword = await argon2.hash(password);
    user.password = hashedPassword;
    user.resetPasswordExpiresAt = undefined;
    user.resetPasswordToken = undefined;
    await user.save();
    await sendPasswordResetSuccessEmail(user.email);
    return res.status(200).json({
      success: true,
      message: "Password reset successfully",
    });
  } catch (error) {
    console.log("errors endin password reset success email", error.message);

    return res.status(200).json({
      success: false,
      message: error.message,
    });
  }
};
export const logout = async (req, res) => {
  const incomingToken = req.cookies.refreshToken;
  if (incomingToken) {
    const tokenHash = crypto
      .createHash("sha256")
      .update(incomingToken)
      .digest("hex");
    await RefreshToken.findOneAndDelete({ token: tokenHash });
  }

  res.clearCookie("refreshToken");
  return res.status(200).json({
    success: true,
    message: "Logout successfully.",
  });
};
export const checkAuth = async (req, res) => {
  try {
    const user = await User.findOne({ _id: req.userId }).select("-password");

    if (!user) {
      return res
        .status(400)
        .json({ success: false, message: "User not ofund" });
    }

    res.status(200).json({
      success: true,
      user,
    });
  } catch (error) {
    console.log("Error in checkAuth", error);
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};
