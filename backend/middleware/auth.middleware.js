export const restrictTo = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: "You are not logged in,Please login.",
      });
    }

    const userRole = req.user.role;
    if (!allowedRoles.includes(userRole)) {
      return res.status(403).json({
        success: false,
        message: "You do not have permission to perfrom this action.",
      });
    }
    next();
  };
};

export const alllowOwnerOrAdmin = (req, res, next) => {
  const userRole = req.user.role;
  const resourceId = req.params.id;
  const currentUserId = req.user._id.toString();

  if (userRole === "admin") {
    return next();
  }
  if (currentUserId === resourceId) {
    return next();
  }
  return res.status(403).json({
    success: false,
    message: "You do not have permession to modify this user.",
  });
};
