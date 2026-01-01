import express from "express";
import protect from "../middlewares/authMiddleware.js";
import { authorizeRoles } from "../middlewares/roleMiddleware.js";

const router = express.Router();

router.get("/user", protect, authorizeRoles("1978", "2003", "1996"), (req,res) => {
    res.json({message: "User data"});
})

router.get("/admin", protect, authorizeRoles("2003"), (req,res) => {
    res.json({message: "Admin data"});
})

router.get("/manager", protect, authorizeRoles("1996", "2003"), (req,res) => {
    res.json({message: "Manager data"});
})

export default router;