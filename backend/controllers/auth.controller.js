import { User } from "../models/user.model.js";
import bcrypt from "bcryptjs";
import { generateVerficationToken } from "../../utils/generateVerificationToken.js";
import { generateTokenAndSetCookie } from "../../utils/generateTokenAndSetCookie.js";
import { sendverificationEmail, sendWelcomeEmail } from "../mailtrap/emails.js";

export const signup = async (req, res) => {
  const { name, email, password } = req.body;
  try {
    if (!email || !name || !password) {
      throw new Error("All fields are required");
    }
    const userAlreadyExists = await User.findOne({ email });

    if (userAlreadyExists) {
      return res.status(400).json({
        success: false,
        message: "User already exists.",
      });
    }
    // const salt = bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(password, 10);
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
    generateTokenAndSetCookie(res, user._id);

    await sendverificationEmail(user.email, verificationToken);

    res.status(201).json({
      success: true,
      message: "User create successfully.",
      user: { ...user._doc, password: undefined },
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      message: error.message,
    });
  }
};

export const verifyEmail = async (req, res) => {
  const { code } = req.body;
  try {
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
    console.log("Error in verifying email", error);
    res.status(500).json({ success: false, message: "server error" });
  }
};
export const login = async (req, res) => {
  res.send("Signup controlelr.");
};

export const logout = async (req, res) => {
  res.send("Signup controlelr.");
};
