import { authenticator } from "otplib";
import qrcode from "qrcode";
import { User } from "../models/user.model";
import crypto from "crypto";
import argon2 from "argon2";

//generte a secret and QRcode

export const generateMfaSecret = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    const secret = authenticator.generateSecret();

    const otpauth = authenticator.keyuri(user.email, "auth", secret);

    const imageUri = await qrcode.toDataURL(otpauth);
    user.mfaSecret = secret;
    await user.save();

    res.status(200).json({
      success: true,
      secret,
      qrCode: imageUri,
    });
  } catch (error) {
    res.status(500).json({
      message: error.message,
    });
  }
};

export const enableMfa = async (req, res) => {
  try {
    const { code } = req.body;
    const user = await User.findById(req.userId);

    const isValid = authenticator.verify({
      token: code,
      secret: user.mfaSecret,
    });

    if (!isValid) {
      return res.status(400).json({
        success: false,
        message: "Invalid code",
      });
    }

    const backupCodes = Array.from({ length: 5 }, () =>
      crypto.randomBytes(4).toString("hex"),
    );

    const hashedBackupCodes = await Promise.all(
      backupCodes.map(async (code) => {
        return {
          code: await argon2.hash(code),
          used: false,
        };
      }),
    );

    user.isMfaEnabled = true;
    user.backupCodes = hashedBackupCodes;
    await user.save();

    res.status(200).json({
      success: true,
      message: "MFA Enabled succesfully ",
      backupCodes,
    });
  } catch (error) {
    res.status(500).json({
      message: error.message,
    });
  }
};
