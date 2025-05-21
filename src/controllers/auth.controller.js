import { asyncHandler } from "../utils/async-handler.js";
import User from "../models/user.model.js";
import { ApiError } from "../utils/api-error.js";
import { ApiResponse } from "../utils/api-response.js";
import {
  emailVerificationMailgenContent,
  forgotPasswordMailgenContent,
  sendEmail,
} from "../utils/mail.js";
import jwt from "jsonwebtoken";
import crypto from "crypto";

// REGISTER USER
const registerUser = asyncHandler(async (req, res) => {
  const { email, fullname, username, password, role } = req.body;
  // Validate input
  if (!fullname || !email || !password || !username || !role) {
    throw new ApiError(400, "All fields are required");
  }
  if (password.length < 8) {
    throw new ApiError(400, "Password must be at least 8 characters");
  }
  try {
    // Check for existing user
    const [existingUserByEmail, existingUserByUsername] = await Promise.all([
      User.findOne({ email }),
      User.findOne({ username })
    ]);

    if (existingUserByEmail) {
      throw new ApiError(409, "User with this email already exists");
    }
    if (existingUserByUsername) {
      throw new ApiError(409, "Username already taken");
    }
    // Create new user
    const newUser = await User.create({
      fullname,
      email,
      username,
      password,
      role,
    });

    if (!newUser) {
      throw new ApiError(500, "Failed to create user");
    }

    // Generate email verification token
    const { hashedToken, unHashedToken, tokenExpiry } = 
      await newUser.generateTemporaryToken();

    newUser.emailVerificationToken = hashedToken;
    newUser.emailVerificationTokenExpiry = tokenExpiry;
    await newUser.save();

    // Send verification email
    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${unHashedToken}`;
    const mailgenContent = emailVerificationMailgenContent(
      newUser.fullname,
      verificationUrl
    );

    await sendEmail({
      email: newUser.email,
      subject: "Verify your email address",
      mailgenContent,
    });

    return res.status(201).json(
      new ApiResponse(
        201,
        {
          user: {
            _id: newUser._id,
            name: newUser.fullname,
            email: newUser.email,
            role: newUser.role,
          },
        },
        "User registered successfully. Please check your email to verify your account."
      )
    );
  } catch (error) {
    console.error("Error registering user:", error);
    throw new ApiError(500, error.message || "Failed to register user");
  }
});

// LOGIN USER
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    throw new ApiError(400, "Email and password are required");
  }

  try {
    const user = await User.findOne({ email }).select("+password");

    if (!user) {
      throw new ApiError(401, "Invalid credentials");
    }

    if (!user.isEmailVerified) {
      throw new ApiError(403, "Please verify your email first");
    }

    const isPasswordValid = await user.isPasswordCorrect(password);
    if (!isPasswordValid) {
      throw new ApiError(401, "Invalid credentials");
    }

    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save();

    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    };

    res.cookie("accessToken", accessToken, cookieOptions);
    res.cookie("refreshToken", refreshToken, cookieOptions);

    return res.status(200).json(
      new ApiResponse(
        200,
        {
          user: {
            _id: user._id,
            fullname: user.fullname,
            email: user.email,
            role: user.role,
          },
          accessToken,
        },
        "User logged in successfully"
      )
    );
  } catch (error) {
    console.error("Login error:", error);
    throw new ApiError(500, error.message || "Login failed");
  }
});

// LOGOUT USER
const logOutUser = asyncHandler(async (req, res) => {
  const userId = req.user?._id;
  if (!userId) {
    throw new ApiError(401, "Unauthorized request");
  }

  try {
    await User.findByIdAndUpdate(
      userId,
      {
        $unset: {
          refreshToken: 1,
        },
      },
      { new: true }
    );

    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
    };

    res.clearCookie("accessToken", cookieOptions);
    res.clearCookie("refreshToken", cookieOptions);

    return res
      .status(200)
      .json(new ApiResponse(200, null, "User logged out successfully"));
  } catch (error) {
    console.error("Logout error:", error);
    throw new ApiError(500, "Failed to logout");
  }
});

// VERIFY EMAIL
const verifyEmail = asyncHandler(async (req, res) => {
  const { token } = req.params;

  if (!token) {
    throw new ApiError(400, "Verification token is required");
  }

  try {
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
      emailVerificationToken: hashedToken,
      emailVerificationTokenExpiry: { $gt: Date.now() },
    });

    if (!user) {
      throw new ApiError(400, "Invalid or expired verification token");
    }

    user.isEmailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationTokenExpiry = undefined;
    await user.save({ validateBeforeSave: false });

    return res
      .status(200)
      .json(new ApiResponse(200, null, "Email verified successfully"));
  } catch (error) {
    console.error("Email verification error:", error);
    throw new ApiError(500, error.message || "Email verification failed");
  }
});

// RESEND VERIFICATION EMAIL
const resendEmailVerification = asyncHandler(async (req, res) => {
  const { email } = req.body;

  if (!email) {
    throw new ApiError(400, "Email is required");
  }

  try {
    const user = await User.findOne({ email });

    if (!user) {
      throw new ApiError(404, "User not found");
    }

    if (user.isEmailVerified) {
      throw new ApiError(400, "Email is already verified");
    }

    const { hashedToken, unHashedToken, tokenExpiry } = 
      await user.generateTemporaryToken();

    user.emailVerificationToken = hashedToken;
    user.emailVerificationTokenExpiry = tokenExpiry;
    await user.save();

    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${unHashedToken}`;
    const mailgenContent = emailVerificationMailgenContent(
      user.fullname,
      verificationUrl
    );

    await sendEmail({
      email: user.email,
      subject: "Verify your email address",
      mailgenContent,
    });

    return res
      .status(200)
      .json(new ApiResponse(200, null, "Verification email sent successfully"));
  } catch (error) {
    console.error("Resend verification error:", error);
    throw new ApiError(500, error.message || "Failed to resend verification email");
  }
});

// REFRESH ACCESS TOKEN
const refreshAccessToken = asyncHandler(async (req, res) => {
  try {
    const incomingRefreshToken = req.cookies?.refreshToken || req.body?.refreshToken;

    if (!incomingRefreshToken) {
      throw new ApiError(401, "Unauthorized request");
    }

    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    const user = await User.findById(decodedToken?._id);

    if (!user) {
      throw new ApiError(401, "Invalid refresh token");
    }

    if (incomingRefreshToken !== user?.refreshToken) {
      throw new ApiError(401, "Refresh token is expired or used");
    }

    const accessToken = user.generateAccessToken();
    const newRefreshToken = user.generateRefreshToken();

    user.refreshToken = newRefreshToken;
    await user.save({ validateBeforeSave: false });

    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    };

    res.cookie("accessToken", accessToken, cookieOptions);
    res.cookie("refreshToken", newRefreshToken, cookieOptions);

    return res.status(200).json(
      new ApiResponse(
        200,
        {
          accessToken,
          refreshToken: newRefreshToken,
        },
        "Access token refreshed"
      )
    );
  } catch (error) {
    console.error("Refresh token error:", error);
    throw new ApiError(401, error?.message || "Invalid refresh token");
  }
});

// FORGOT PASSWORD REQUEST
const forgotPasswordRequest = asyncHandler(async (req, res) => {
  const { email } = req.body;

  if (!email) {
    throw new ApiError(400, "Email is required");
  }

  try {
    const user = await User.findOne({ email });

    if (!user) {
      throw new ApiError(404, "User not found");
    }

    const { hashedToken, unHashedToken, tokenExpiry } = 
      await user.generateTemporaryToken();

    user.passwordResetToken = hashedToken;
    user.passwordResetTokenExpiry = tokenExpiry;
    await user.save({ validateBeforeSave: false });

    const passwordResetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${unHashedToken}`;
    const mailgenContent = forgotPasswordMailgenContent(
      user.fullname,
      passwordResetUrl
    );

    await sendEmail({
      email: user.email,
      subject: "Reset your password",
      mailgenContent,
    });

    return res
      .status(200)
      .json(new ApiResponse(200, null, "Password reset email sent successfully"));
  } catch (error) {
    console.error("Forgot password error:", error);
    throw new ApiError(500, error.message || "Failed to send password reset email");
  }
});

// RESET FORGOTTEN PASSWORD
const resetForgottenPassword = asyncHandler(async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    throw new ApiError(400, "Token and new password are required");
  }

  if (newPassword.length < 8) {
    throw new ApiError(400, "Password must be at least 8 characters");
  }

  try {
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetTokenExpiry: { $gt: Date.now() },
    });

    if (!user) {
      throw new ApiError(400, "Invalid or expired password reset token");
    }

    user.password = newPassword;
    user.passwordResetToken = undefined;
    user.passwordResetTokenExpiry = undefined;
    await user.save();

    return res
      .status(200)
      .json(new ApiResponse(200, null, "Password reset successfully"));
  } catch (error) {
    console.error("Password reset error:", error);
    throw new ApiError(500, error.message || "Failed to reset password");
  }
});

// CHANGE CURRENT PASSWORD
const changeCurrentPassword = asyncHandler(async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.user?._id;

  if (!userId) {
    throw new ApiError(401, "Unauthorized request");
  }

  if (!currentPassword || !newPassword) {
    throw new ApiError(400, "Current and new password are required");
  }

  if (newPassword.length < 8) {
    throw new ApiError(400, "New password must be at least 8 characters");
  }

  try {
    const user = await User.findById(userId).select("+password");

    if (!user) {
      throw new ApiError(404, "User not found");
    }

    const isPasswordCorrect = await user.isPasswordCorrect(currentPassword);
    if (!isPasswordCorrect) {
      throw new ApiError(401, "Current password is incorrect");
    }

    user.password = newPassword;
    await user.save();

    return res
      .status(200)
      .json(new ApiResponse(200, null, "Password changed successfully"));
  } catch (error) {
    console.error("Change password error:", error);
    throw new ApiError(500, error.message || "Failed to change password");
  }
});

// GET CURRENT USER INFO
const getCurrentUser = asyncHandler(async (req, res) => {
  const userId = req.user?._id;

  if (!userId) {
    throw new ApiError(401, "Unauthorized request");
  }

  try {
    const user = await User.findById(userId).select(
      "-password -refreshToken -emailVerificationToken -emailVerificationTokenExpiry -passwordResetToken -passwordResetTokenExpiry"
    );

    if (!user) {
      throw new ApiError(404, "User not found");
    }

    return res.status(200).json(
      new ApiResponse(
        200,
        user,
        "User profile fetched successfully"
      )
    );
  } catch (error) {
    console.error("Get user error:", error);
    throw new ApiError(500, error.message || "Failed to fetch user profile");
  }
});

export {
  registerUser,
  loginUser,
  logOutUser,
  verifyEmail,
  resendEmailVerification,
  refreshAccessToken,
  forgotPasswordRequest,
  resetForgottenPassword,
  changeCurrentPassword,
  getCurrentUser,
};