import mongoose, { Schema } from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { AvaiableUserRoles, UserRoleEnum } from "../utils/constant.js";
const userSchema = new Schema(
  {
    avatar: {
      type: {
        url: { type: String },
        localpath: { type: String },
      },
      default: {
        url: `https://placehold.co/600x400`,
        localpath: " ",
      },
    },
    username: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    fullname: {
      type: String,
      required: true,
    },
    password: {
      type: String,
      required: [true, "password is required"],
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
    forgotPasswordExpiry: {
      type: Date,
    },
    forgotPasswordToken: {
      type: String,
    },
    refreshToken: {
      type: String,
    },
    emailVerificationToken: {
      type: String,
    },
    emailVerificationTokenExpiry: {
      type: Date,
    },
    role: {
      type: String,
      enum: AvaiableUserRoles,
      default: UserRoleEnum.MEMBER,
      required: true,
    },
  },

  { timestamps: true },
);
// to save to db when modified is changed ( hashing is an  expensive ops)
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

userSchema.methods.isPasswordCorrect = async function (password) {
  return await bcrypt.compare(password, this.password);
};
userSchema.methods.generateAccessToken = function () {
  return jwt.sign(
    {
      _id: this._id,
      email: this.email,
      username: this.username,
    },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: "24h",
    },
  );
};

userSchema.methods.genrateRefreshToken = function () {
  return jwt.sign(
    {
      _id: this._id,
      username: this.username,
    },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: "30d" },
  );
};
userSchema.methods.generateTemporaryToken = async function () {
  const unHashedToken = crypto.randomBytes(32).toString("hex");
  const hashedToken = crypto.createHash("sha256").update(unHashedToken).digest("hex");
  const tokenExpiry = Date.now() + 30 * 60 * 1000;

  return {hashedToken ,unHashedToken,tokenExpiry};
};
export default mongoose.model("User", userSchema);
