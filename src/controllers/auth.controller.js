import { asyncHandler } from "../utils/async-handler.js";
import User from "../models/user.model.js";
import { ApiError } from "../utils/api-error.js";
import { ApiResponce } from "../utils/api-responce.js";
import jwt from "jsonwebtoken";
import crypto from "crypto";

// REGISTER USER
const registerUser = asyncHandler(async (req, res) => {
  try {
    const { email, fullname, username, password } = req.body;
    const userExists = await User.findOne({ email });
    if (userExists) {
      throw new ApiError(400, "User already exists");
    }
    const newUser = await User.create({ email, fullname, username, password });
    const token = crypto.randomBytes(32).toString("hex");
    newUser.emailVerificationToken = token;
    newUser.emailVerificationTokenExpiry = Date.now() + 1000 * 60 * 60 * 24; // 24h
    await newUser.save();
    await sendVerificationEmail(newUser.email, token);
    return res.status(201).json(
      new ApiResponce(
        201,
        {
          user: {
            _id: newUser._id,
            username: newUser.username,
            email: newUser.email,
            role: newUser.role,
          },
        },
        "User registered successfully. Please check your email to verify your account",
      ),
    );
  } catch (error) {
    console.error("Error registering user:", error);
    throw new ApiError(500, "Internal server error while registering user");
  }
});
// VERIFY EMAIL
const verifyEmail = asyncHandler(async (req, res) => {
  try {
    const { token } = req.params;
    const user = await User.findOne({
      emailVerificationToken: token,
      emailVerificationTokenExpiry: { $gt: Date.now() },
    });
    if (!user) {
      throw new ApiError(400, "User already exists");
    }
    user.isEmailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationTokenExpiry = undefined;
    await user.save();
    return res.status(201).json(
      new ApiResponce(
        201,
        {
          user: { username: user.username},
        },
        "Email verified successfully",
      ),
    );
  } catch (error) {
    console.error("Error Email verification:", error);
    throw new ApiError(500, "Error Email verification");
  }
});
// LOGIN USER
const loginUser = asyncHandler(async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await user.isPasswordCorrect(password))) {
      return res.status(400).json(new ApiError(400, "Invalid crrendtials"));
    }
    const accessToken = user.generateAccessTokens();
    const refreshToken = user.genrateRefreshToken();
    user.refreshToken = refreshToken;
    await user.save();
    return res.status(201).json(
      new ApiResponce(
        201,
        {
          user: {
            username: user.username
          },
        },
        "User loggedin successfully.",
      ),
    );
  } catch (error) {
    console.error("Error registering user:", error);
    throw new ApiError(500, "Invalid crrendtials");
  }
});
// LOGOUT USER
const logOutUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.User._id);
  if (!user) {
    return res.status(401).json({ message: "Invalid user" });
  }
  user.refreshToken = "";
  await user.save();
  res.clearCookie("accessToken");
  res.clearCookie("refreshToken");
  return res
    .status(201)
    .json(new ApiResponce(200, null, "user successfully logged out"));
});
// SEND VERIFICATION MAIL
const resendEmailVerification = asyncHandler(async (req, res) => {
  const { email } = req.body;
  if (!email) throw new Error("Email is required");
  const user = await User.findOne({ email });
  if (!user) throw new Error("User not found");
  if (user.isEmailVerified) throw new Error("Email already verified");
  const token = crypto.randomBytes(32).toString("hex");
  user.emailVerificationToken = crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
  user.emailVerificationTokenExpiry = Date.now() + 1000 * 60 * 60 * 24;
  await user.save();
  const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;
  await sendEmail({
    to: email,
    subject: "Resend Email Verification",
    text: `Click to verify: ${verificationUrl}`,
  });
  return res
    .status(201)
    .json(new ApiResponce(200, null, "email reset email sent successfully"));
});
// FORGET PASSWORD
const forgotPasswordRequest = asyncHandler(async (req, res) => {
  const { email } = req.body
  const user = await User.findOne({ email });
  if (!user) throw new ApiError(400, "User already exists");
  const token = crypto.randomBytes(32).toString("hex");
  user.forgotPasswordToken = crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
  user.forgotPasswordExpiry = Date.now() + 1000 * 60 * 60 * 24;
  await user.save();
  const resetUrl = `${process.env.FRONTEND_URL}/resetpassword?token=${token}`;
  await sendEmail({
    to: email,
    subject: "Forgot Password Request",
    text: `Click here to verify ${resetUrl}`,
  });
  return res
    .status(201)
    .json(new ApiResponce(200, null, "Password reset email sent successfully"));
});
const resetForgottenPassword = asyncHandler(async (req, res) => {
  const { token, newPassword } = req.body;
  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
  const user = await User.findOne({
    forgotPasswordToken: hashedToken,
    forgotPasswordExpiry: { $gt: Date.now() },
  });
  if (!user) throw new ApiError(400, "something went wrong");
  user.password = newPassword;
  user.forgotPasswordToken = undefined;
  user.forgotPasswordExpiry = undefined;
  await user.save();
  return res
    .status(201)
    .json(new ApiResponce(200, null, "update password sucessfully"));
});
// CHANGE REFRESH TOKEN
const refreshAccessToken = asyncHandler(async (req, res) => {
  const refreshToken = req.cookies;
  if (!refreshToken) throw new ApiError("400", "ther's no refreshToken");
  const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
  const user = await User.findById(decoded._id);
  if (!user || user.refreshToken !== refreshToken)
    throw new ApiError(200, "somehting went wrong");
  const newAccessToken = user.generateAccessTokens();
  const newRefreshToken = user.genrateRefreshToken();
  user.refreshToken = newRefreshToken;
  await user.save()
  res.cookie("accessToken", newAccessToken, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
  });
  res.cookie("refreshToken", newRefreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
  });
  return res
    .status(201)
    .json(
      new ApiResponce("201", null, "generated refreshAccessToken sucessfully"),
    );
});
// CHANGE CURRENT PASSWORD
const changeCurrentPassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const user = await User.findById(req.user._id);
  const isMatch = await user.isPasswordCorrect(oldPassword);
  if (!isMatch) throw new Error("Old password is incorrect");

  user.password = newPassword;
  await user.save();
  return res
    .status(201)
    .json(new ApiResponce("201", null, "Password updated successfully"));
});
// USER INFO
const getCurrentUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id).select(
    "-password -refreshToken",
  );
  return res.status(201).json(new ApiResponce("201", null, user));
});
export {
  registerUser,
  loginUser,
  logOutUser,
  verifyEmail,
  resendEmailVerification,
  resetForgottenPassword,
  refreshAccessToken,
  forgotPasswordRequest,
  changeCurrentPassword,
  getCurrentUser,
};
