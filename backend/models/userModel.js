import mongoose, { Types } from "mongoose";

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, trim: true, },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true, },
    password: { type: String, required: true, trim: true },
    profileImage: {
  public_id: { type: String },
  url: { type: String },
},
    isEmailVerified: { type: Boolean, default: false },
    emailOtp: { type: String, default: ''},
    emailOtpExpire: { type: Date},
    resetpasswordToken: { type: String},
    resetpasswordTokenExpireAt: { type: Date},

    role: { type: String, enum: [1978, 2003, 1996], default: 1978 },
},
    {
        timestamps: true,
    }
);

const User = mongoose.model("User", userSchema);
export default User;