import User from "../models/userModel.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import optMailTemplate from "../utils/otpMailTemplate.js";

import { generateAccessToken, generateRefreshToken } from "../utils/token.js";
import {
  accessTokenCookieOptions,
  refreshTokenCookieOptions,
} from "../utils/cookieOptions.js";
import generateOTP from "../utils/generateOtp.js";
import sendmail from "../nodemailer/sandmail.js";
import hashOtp from "../utils/hashOtp.js";
import transporter from "../nodemailer/config.js";
import crypto from "crypto";
import hashToken from "../utils/hashToken.js";
import uploadImages from "../services/ImageKit.js";

export const register = async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(409).json({ message: "User already exists" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    const otp = generateOTP();
    const hashedotp = hashOtp(otp);

    const newUser = await User.create({
      username,
      email,
      password: hashedPassword,
      emailOtp: hashedotp,
      emailOtpExpire: Date.now() + 10 * 60 * 1000,
      lastOtpSentAt: Date.now(),
    });

    await sendmail({
      to: email,
      subject: "Verify your email",
      html: optMailTemplate(username, otp),
    });

    res.status(201).json({
      message: "Registration successful. OTP sent to email.",
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;

  // 1. Find user
  const user = await User.findOne({ email }).select("+password");
  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const isVarified = user.isEmailVerified;

  if (!isVarified)
    return res.status(400).json({ message: "User Not Varified" });

  // 2. Generate tokens
  const accessToken = generateAccessToken(user._id);
  const refreshToken = generateRefreshToken(user._id);

  // 3. Store tokens in HTTP-only cookies
  res
    .cookie("accessToken", accessToken, accessTokenCookieOptions)
    .cookie("refreshToken", refreshToken, refreshTokenCookieOptions)
    .status(200)
    .json({
      user: {
        _id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
};

export const logout = (req, res) => {
  res
    .clearCookie("accessToken")
    .clearCookie("refreshToken")
    .status(200)
    .json({ message: "Logged out successfully" });
};

export const me = async (req, res) => {
  try {
    // req.user comes from protect middleware
    if (!req.user) {
      return res.status(401).json({ message: "Not authenticated" });
    }

    res.status(200).json({
      user: {
        id: req.user._id,
        name: req.user.name,
        email: req.user.email,
        role: req.user.role,
      },
    });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
};

export const refreshToken = (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ message: "No refresh token" });
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    const newAccessToken = jwt.sign(
      { id: decoded.id },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: "20s" }
    );

    res.cookie("accessToken", newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 20 * 1000,
    });

    return res.json({ message: "Access token refreshed" });
  } catch (err) {
    return res.status(403).json({ message: "Refresh token expired" });
  }
};

export const verifyOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    // 1️⃣ Validate input
    if (!email || !otp) {
      return res.status(400).json({
        message: "Email and OTP are required",
      });
    }

    // 2️⃣ Find user
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    // 3️⃣ Block if already verified
    if (user.isEmailVerified) {
      return res.status(400).json({
        message: "Email already verified",
      });
    }

    // 4️⃣ Check OTP expiry
    if (!user.emailOtp || user.emailOtpExpire < Date.now()) {
      return res.status(400).json({
        message: "OTP expired. Please resend OTP.",
      });
    }

    // 5️⃣ Hash incoming OTP (string safe)
    const hashedOtp = hashOtp(String(otp));

    // 6️⃣ Compare hashed OTP
    if (hashedOtp !== user.emailOtp) {
      return res.status(400).json({
        message: "Invalid OTP",
      });
    }

    // 7️⃣ Mark verified & cleanup
    user.isEmailVerified = true;
    user.emailOtp = undefined;
    user.emailOtpExpire = undefined;

    await user.save();

    return res.status(200).json({
      message: "Email verified successfully",
    });
  } catch (error) {
    console.error("Verify OTP Error:", error);
    return res.status(500).json({
      message: "Server error",
    });
  }
};

export const resendOtp = async (req, res) => {
  try {
    const { email } = req.body;

    // 1️⃣ Validate input
    if (!email) {
      return res.status(400).json({
        message: "Email is required",
      });
    }

    // 2️⃣ Find user
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    // 3️⃣ Already verified?
    if (user.isEmailVerified) {
      return res.status(400).json({
        message: "Email already verified",
      });
    }

    if (
      user.lastOtpSentAt &&
      Date.now() - user.lastOtpSentAt.getTime() < 60 * 1000
    ) {
      return res.status(429).json({
        message: "Please wait 60 seconds before resending OTP",
      });
    }

    // 4️⃣ Generate new OTP
    const otp = generateOTP();
    const hashedOtp = hashOtp(otp);

    // 5️⃣ Overwrite OTP + expiry
    user.emailOtp = hashedOtp;
    user.emailOtpExpire = Date.now() + 10 * 60 * 1000;
    user.lastOtpSentAt = new Date();

    await user.save();

    // 6️⃣ Send OTP email
    await sendmail({
      to: email,
      subject: "Your new OTP",
      html: `
        <h2>Hello ${user.username}</h2>
        <p>Your new OTP is:</p>
        <h1>${otp}</h1>
        <p>This OTP will expire in 10 minutes.</p>
      `,
    });

    // 7️⃣ Success response
    return res.status(200).json({
      message: "OTP resent successfully",
    });
  } catch (error) {
    console.error("Resend OTP Error:", error);
    return res.status(500).json({
      message: "Server error",
    });
  }
};

export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    // 1️⃣ Validate input
    if (!email) {
      return res.status(400).json({
        message: "Email is required",
      });
    }

    // 2️⃣ Find user
    const user = await User.findOne({ email });

    // ❗ Do NOT reveal user existence
    if (!user) {
      return res.status(200).json({
        message: "If account exists, reset link sent to email",
      });
    }

    // 3️⃣ Generate reset token
    const resetToken = crypto.randomBytes(32).toString("hex");

    // 4️⃣ Hash token before saving
    user.resetpasswordToken = hashToken(resetToken);
    user.resetpasswordTokenExpireAt = Date.now() + 10 * 60 * 1000; // 10 min

    await user.save();

    // 5️⃣ Create reset URL
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

    // 6️⃣ Send email
    await transporter.sendMail({
      from: `"Support" <${process.env.GOOGLE_APP_EMAIL}>`,
      to: user.email,
      subject: "Password Reset Request",
      html: `
        <p>You requested a password reset</p>
        <p>This link expires in <b>10 minutes</b></p>
        <a href="${resetUrl}">Reset Password</a>
      `,
    });

    return res.status(200).json({
      message: "If account exists, reset link sent to email",
    });
  } catch (error) {
    console.error("Forgot Password Error:", error);
    return res.status(500).json({
      message: "Server error",
    });
  }
};

export const resetPassword = async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({ message: "Password is required" });
    }

    const user = await User.findOne({
      resetpasswordToken: token,
      resetpasswordTokenExpireAt: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ message: "Token is invalid or expired" });
    }

    user.password = await bcrypt.hash(password, 10);
    user.resetpasswordToken = undefined;
    user.resetpasswordTokenExpireAt = undefined;

    await user.save();

    await transporter.sendMail({
      from: `"Support" <${process.env.GOOGLE_APP_EMAIL}>`,
      to: user.email,
      subject: "Password Reset Successfully",
      html: `<p>Your password has been reset successfully.</p>`,
    });

    res.status(200).json({ message: "Password reset successful" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server Error" });
  }
};


export const uploadImage = async (req,res) => {
    try {
    if (!req.file) {
      return res.status(400).json({ message: "No file uploaded" });
    }

    const result = await uploadImages(req.file);

    res.status(200).json({
      url: result.url,
      fileId: result.fileId
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
} 
