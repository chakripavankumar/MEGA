import mongoose, { Schema } from "mongoose";
const userSchema = new Schema(
  { avatar: {
      type: {
        url: {type: String},
        localpath: {type: String},
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
    forgotPasswordExpiry:  Date,
    refreshToken: String,
    emailVerificationToken:  String,
    emailVerificationExpiry: Date,
  },
  { timestamps: true },
);
export default mongoose.model("User" ,  userSchema)