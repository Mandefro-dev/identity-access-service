import mongoose from "mongoose";

const refreshTokenSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    token: {
      type: String,
      required: true,
      index: true,
    },
    expiresAt: {
      type: Date,
      required: true,
    },
    revoked: { type: Boolean, default: false },
    replaceByToken: { type: String },
    ipAddress: { type: String },
    userAgent: { type: String },
    deviceInfo: {
      os: { type: String },
      browser: { type: string },
      device: { type: string },
    },

    lastActive: { type: Date, default: Date.now },
  },
  {
    timestamps: true,
  },
);
refreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
export const RefreshToken = mongoose.model("RefreshToken", refreshTokenSchema);
