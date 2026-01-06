import express, { urlencoded } from "express";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import cors from "cors";
import connectDB from "./config/db.js";
import authUserRoute from "./routes/authUserRoute.js";
import userRoute from './routes/userRoute.js';

dotenv.config();

const app = express();

app.use(cors({
    origin: "http://localhost:5173",
    credentials: true,
}))
app.use(cookieParser());

//Middlewares
app.use(express.json());
app.use(express.urlencoded({ express: false}))
<<<<<<< HEAD

=======
>>>>>>> 31e4fb7589e4ee33f76c591686d1e8ef54328402

//Routes
app.use("/api/auth", authUserRoute);
app.use("/api/users", userRoute);

const PORT = process.env.PORT || 5000;
connectDB();
app.listen(PORT, () => {
    console.log("Server is Running");
})
