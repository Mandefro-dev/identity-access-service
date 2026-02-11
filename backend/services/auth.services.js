import { OAuth2Client } from "google-auth-library";
import { User } from "../models/user.model.js";

const clinet = new OAuth2Client(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  process.GOOGLE_REDIRECT_URI,
);

export const googleAuthService = async (code) => {
  const { tokens } = await clinet.getToken(code);
  const idToken = tokens.id_token;

  const ticket = await clinet.verifyIdToken({
    idToken,
    audience: process.env.CLIENT_ID,
  });
  const payload = ticket.getPayload();
  const { sub: googleId, email, name, picture, email_verified } = payload;

  if (!email_verified) {
    throw new Error("Google Email is not verified.");
  }

  let user = await User.findOne({ $or: [{ googleId }, { email }] });
  if (user) {
    if (!user.googleId) {
      user.googleId = googleId;
      user.avatar = user.avatar || picture;
      if (user.authProvider === "local") user.authProvider = "mixed";

      await user.save();
    }
    return user;
  }

  const newUser = await User.create({
    email,
    name,
    googleId,
    avatar: picture,
    authProvider: "google",
    isVerified: true,
  });

  return newUser;
};
