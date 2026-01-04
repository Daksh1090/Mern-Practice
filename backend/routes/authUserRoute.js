import express from "express";
import { login, logout, me, register, refreshToken, verifyOtp, resendOtp, forgotPassword, resetPassword } from "../controllers/authUserController.js";
import protect from "../middlewares/authMiddleware.js";


const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/logout", logout);
router.get("/me", protect, me);
router.post("/refresh", refreshToken);
router.post("/verifyotp", verifyOtp)
router.post("/resendOtp", resendOtp)
router.post("/forgotpassword", forgotPassword)
router.post("/reset-token/:token",  resetPassword)

export default router;