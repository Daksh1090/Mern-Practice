import express from "express";
import { login, logout, me, register, refreshToken, verifyOtp, resendOtp, forgotPassword, uploadFileController } from "../controllers/authUserController.js";
import protect from "../middlewares/authMiddleware.js";
import upload from '../multer/upload.js';
import { uploadSingleImage } from "../multer/uploadMiddleware.js";

const router = express.Router();

router.post("/register",uploadSingleImage("profile"), register);
router.post("/login", login);
router.post("/logout", logout);
router.get("/me", protect, me);
router.post("/refresh", refreshToken);
router.post("/verifyotp", verifyOtp)
router.post("/resendOtp", resendOtp)
router.post("/forgotpassword", forgotPassword)
// router.post("/upload", upload.single("image"), uploadFileController);

export default router;