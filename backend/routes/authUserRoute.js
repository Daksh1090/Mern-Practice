import express from "express";
import { login, logout, me, register, refreshToken } from "../controllers/authUserController.js";
import protect from "../middlewares/authMiddleware.js";


const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/logout", logout);
router.get("/me", protect, me);
router.post("/refresh", refreshToken);

export default router;