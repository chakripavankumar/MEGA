import { Router } from "express";
import {
  registerUser,
  verifyEmail,
  loginUser,
  logOutUser,
  resendEmailVerification,
  forgotPasswordRequest,
  resetForgottenPassword,
  changeCurrentPassword,
  getCurrentUser,
  refreshAccessToken
} from "../controllers/auth.controller.js";
const router = Router();

router.route("/getUser").get(getCurrentUser);
router.route("/register").post(registerUser);
router.route("/login").post(loginUser);
router.route("/logout").post(logOutUser);
router.route("/verifyEmail").post(verifyEmail);
router.route("/resendVerificationEmail").post(resendEmailVerification);
router.route("/forgotPasswordRequest").post(forgotPasswordRequest);
router.route("/resetForgottenPassword").post(resetForgottenPassword);
router.route("/changeCurrentPassword").post(changeCurrentPassword);
router.route("/refreshAccessToken").post(refreshAccessToken);

export default router;
