import { asyncHandler } from "../utils/async-handler.js";
const registerUser = asyncHandler(async (req, res) => {
  const { email, username, password, role } = req.body;
});

const loginUser = asyncHandler(async (req, res) => {
  const { email, username, password, role } = req.body;
});

const loginOutUser = asyncHandler(async (req, res) => {
  const { email, username, password, role } = req.body;
});
const verifyEmail = asyncHandler(async (req, res) => {
  const { email, username, password, role } = req.body;

  //validation
});
const resendEmailVerification = asyncHandler(async (req, res) => {
  const { email, username, password, role } = req.body;

  //validation
});
const resetForgottenPassword = asyncHandler(async (req, res) => {
  const { email, username, password, role } = req.body;

  //validation
});
const refreshAccessToken = asyncHandler(async (req, res) => {
  const { email, username, password, role } = req.body;

  //validation
});
const forgotPasswordRequest = asyncHandler(async (req, res) => {
  const { email, username, password, role } = req.body;

  //validation
});
const changeCurrentPassword = asyncHandler(async (req, res) => {
  const { email, username, password, role } = req.body;

  //validation
});
const getCurrentUser = asyncHandler(async (req, res) => {
  const { email, username, password, role } = req.body;
});
export {
    registerUser,
    loginUser,
    loginOutUser,
    verifyEmail,
    resendEmailVerification,
    resetForgottenPassword,
    refreshAccessToken,
    forgotPasswordRequest,
    changeCurrentPassword,
    getCurrentUser
};
