import { RefreshToken } from "../models/refreshToken.model.js";
import crypto from "crypto";

export const getActiveSessions = async (req, res) => {
  try {
    const sessions = await RefreshToken.find({
      userId: req.userId,
      revoked: false,
      expiresAt: { $gt: Date.now() },
    })
      .select("ipAddress deviceInfo lastActive createdAt _id,token")
      .sort({ lastActive: -1 })
      .lean();

    //whcih session is the current one

    const currentToken = req.cookies.refreshToken;
    let currentTokenHash = "";
    if (currentToken) {
      currentTokenHash = crypto
        .createHash("sha256")
        .update(currentToken)
        .digest("hex");
    }

    const sessionData = sessions.map((s) => {
      const isCurrent = s.token === currentTokenHash;
      const { token, ...rest } = s;

      return {
        ...rest,
        isCurrent,
      };
    });

    res.status(200).json({
      success: true,
      sessions: sessionData,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
//revoke a session

export const revokeSession = async (req, res) => {
  try {
    const { sessionId } = req.params;
    const userId = req.userId;
    const session = await RefreshToken.findOne({ _id: sessionId, userId });

    if (!session) {
      return res.status(404).json({
        message: "Session not found",
      });
    }

    await RefreshToken.deleteOne({ _id: sessionId });
    res.status(200).json({
      success: true,
      message: "Session revoked successFully",
    });
  } catch (error) {
    res.status(500).json({
      error: error.message,
    });
  }
};
