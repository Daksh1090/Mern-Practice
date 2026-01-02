import User from "../models/userModel.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import optMailTemplate from "../utils/otpMailTemplate.js";

import {generateAccessToken, generateRefreshToken,} from "../utils/token.js";
import {accessTokenCookieOptions, refreshTokenCookieOptions,} from "../utils/cookieOptions.js";
import generateOTP from "../utils/generateOtp.js";
import sendmail from "../nodemailer/sandmail.js";

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
    // create otp 
    const otp = generateOTP();

    const newUser = await User.create({
      username,
      email,
      password: hashedPassword,
      emailOtp: otp,
      emailOtpExpire: Date.now() + 10 * 60 * 1000,
    });

    await sendmail({
      to: email,
      subject: 'Verify your email',
      html: optMailTemplate(username, otp),
    })

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
    const decoded = jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_SECRET
    );

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

    // 3️⃣ Check OTP match
    if (user.emailOtp !== otp) {
      return res.status(400).json({
        message: "Invalid OTP",
      });
    }

    // 4️⃣ Check OTP expiry
    if (user.emailOtpExpires < Date.now()) {
      return res.status(400).json({
        message: "OTP expired",
      });
    }

    // 5️⃣ Mark email as verified
    user.isEmailVerified = true;
    user.emailOtp = undefined;
    user.emailOtpExpires = undefined;

    await user.save();

    // 6️⃣ Success response
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
