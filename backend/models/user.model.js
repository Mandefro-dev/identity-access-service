import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
    },

    password: {
      type: String,
    },
    name: {
      type: String,
      required: true,
    },
    lastLogin: {
      type: Date,
      default: Date.now(),
    },
    role: {
      type: String,
      enum: ["user", "moderator", "admin"],
      default: "user",
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    accountStatus: {
      type: String,
      enum: ["active", "suspended", "pro"],
      default: "active",
    },
    trustScore: { type: Number, default: 10 },

    isMfaEnabled: { type: Boolean, default: false },

    mfaSecret: { type: String },
    lastLoginIp: String,
    department: {
      type: String,
      enum: ["engineering", "billing", "support", "none"],
      default: "none",
    },

    backupCodes: [
      {
        code: {
          type: String,
          required: true,
        },
        used: {
          type: Boolean,
          default: false,
        },
      },
    ],
    resetPasswordToken: String,
    resetPasswordExpiresAt: Date,
    verificationToken: String,
    verificationTokenExpiresAt: Date,

    googleId: {
      type: String,
      unique: true,
      sparse: true,
    },
    githubId: { type: String, unique: true, sparse: true },
    avatar: { type: String },
    authProvider: {
      type: String,
      enum: ["local", "google", "github", "mixed"],
      default: "local",
    },
  },
  { timestamps: true },
);
//timestaps gives u createdAt and upateAt filed will be automatically added into the document.
export const User = mongoose.model("User", userSchema);
