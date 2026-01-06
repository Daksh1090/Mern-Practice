import express from "express";
import { login, logout, me, register, refreshToken, verifyOtp, resendOtp, forgotPassword, uploadImage } from "../controllers/authUserController.js";
import protect from "../middlewares/authMiddleware.js";
import upload from "../multer/multer.js";

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/logout", logout);
router.get("/me", protect, me);
router.post("/refresh", refreshToken);
router.post("/verifyotp", verifyOtp)
router.post("/resendOtp", resendOtp)
router.post("/forgotpassword", forgotPassword)
router.post("/upload", upload.single("image"), uploadImage)

export default router;