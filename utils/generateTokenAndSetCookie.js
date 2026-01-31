import jwt from "jsonwebtoken";

export const generateTokenAndSetCookie = async (res, userId) => {
  const token = jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });

  res.cookie("token", token, {
    httpOnly: true, //to protect from XSS
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict", //to prevent attack
    maxAge: 1000 * 60 * 60 * 24 * 7, //days
  });

  return token;
};
