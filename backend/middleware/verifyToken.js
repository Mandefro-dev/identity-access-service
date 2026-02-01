import jwt from "jsonwebtoken";
export const verifyToken = (req, res, next) => {
  const token = req.cookies.token;
  try {
    if (!token)
      return res
        .status(401)
        .json({ success: false, message: "Unauthorized - no token provided" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded)
      return res
        .status(401)
        .json({ success: false, message: "invalide token" });
    req.userId = decoded.userId;
    next();
  } catch (error) {
    console.log("erron in verifytoken", error);
    res.status(500).json({ success: false, message: "server error" });
  }
};
