// import jwt from "jsonwebtoken";
// export const verifyToken = (req, res, next) => {
//   const token = req.cookies.token;
//   try {
//     if (!token)
//       return res
//         .status(401)
//         .json({ success: false, message: "Unauthorized - no token provided" });

//     const decoded = jwt.verify(token, process.env.JWT_SECRET);
//     if (!decoded)
//       return res
//         .status(401)
//         .json({ success: false, message: "invalide token" });
//     req.userId = decoded.userId;
//     next();
//   } catch (error) {
//     console.log("erron in verifytoken", error);
//     res.status(500).json({ success: false, message: "server error" });
//   }
// };
import jwt from "jsonwebtoken";

export const verifyAccessToken = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  const token = authHeader.split(" ")[1];

  try {
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    req.userId = payload.userId;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Token expired" });
  }
};
