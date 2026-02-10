export const canModifyResource = (Model) => {
  return async (req, res, next) => {
    try {
      const user = req.user;
      const resourceId = req.params.id;

      const resource = await Model.findById(resourceId);
      if (!resource)
        return res.status(404).json({ message: "Resource Not found" });
      //admin can do anything
      if (user.role === "admin") return next();
      //user must own it
      const isOwner = resource.ownerId.toString() === user._id.toString();
      const isLocked = resource.status === "archived" || resource.isLocked;
      const canUpdate = isOwner && !isLocked && user.isVerified;

      if (!canUpdate) {
        return res.status(403).json({
          success: false,
          message:
            "Access Denied: Resource is locked or account is not verfified.",
          attributes: {
            isOwner,
            isLocked,
            isVerified: user.isVerified,
          },
        });
      }

      req.resource = resource;
      next();
    } catch (error) {
      next(errors);
    }
  };
};

export const enviromentGuard = (req, res, next) => {
  const user = req.user;
  if (req.method === "DELETE" && !user.isMfaEnabled) {
    return res.status(403).json({
      message: "MFA must be enabled to perfrom destructive actios",
    });
  }
  if (user.accountStatus === "suspended") {
    return res.status(403).json({
      message: "Your account is restircted.",
    });
  }

  next();
};
