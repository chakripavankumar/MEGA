import { body } from "express-validator";
import { AvaiableUserRoles, AvaiableTaskStatus } from "../utils/constant.js";

const userRegisterValidator = () => {
  return [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("Email is required ")
      .isEmail()
      .withMessage("Email is required "),
    body("username")
      .trim()
      .notEmpty()
      .withMessage("Username is required ")
      .isLowercase()
      .withMessage("Username must be lowercase")
      .isLength({ min: 3 })
      .withMessage("Username must be at lease 3 characters long"),
    body("password").trim().notEmpty().withMessage("Password is required"),
    body("fullname")
      .optional()
      .trim()
      .notEmpty()
      .withMessage("Full name is required"),
  ];
};

const userLoginValidator = () => {
  return [
    body("email").optional().isEmail().withMessage("Email is invalid"),
    body("username").optional(),
    body("password").notEmpty().withMessage("password is required"),
  ];
};
const userCurrentPasswordChangeValidator = () => {
  return [
    body("oldpassword").notEmpty().withMessage("oldpassword is required"),
    body("newpassword").notEmpty().withMessage("newpassword is required"),
  ];
};
const userForgetPasswordValidator = () => {
  return [
    body("email")
      .notEmpty()
      .withMessage("email is required")
      .isEmail()
      .withMessage("email is required"),
  ];
};
const userResetForgottenPasswordValidator = () => {
  return [body("newPassword").notEmpty().withMessage("Password is required")];
};
const projectValidator = () => {
  return [
    body("name").notEmpty().withMessage("name is required"),
    body("description").optional(),
  ];
};
const addMemberTotheProjectValidator = () => {
  return [
    body("email")
      .notEmpty()
      .withMessage("email is required")
      .isEmail()
      .withMessage("email is required"),
    body("role")
      .notEmpty()
      .withMessage("role is requied")
      .isIn(AvaiableUserRoles)
      .withMessage("role is invalid"),
  ];
};
const createTaskValidator = () => {
  return [
    body("title").notEmpty().withMessage("title is required"),
    body("description").optional(),
    body("assingedTo").notEmpty().withMessage("assingedTo is required"),
    body("status")
      .optional()
      .notEmpty()
      .withMessage("Status is required")
      .isIn(AvaiableTaskStatus),
  ];
};
const updateTaskvalidator = () => {
  return [
    body("title").optional(),
    body("description").optional(),
    body("status")
      .optional()
      .isIn(AvaiableTaskStatus)
      .withMessage("Status is required"),
    body("assingedTo").optional(),
  ];
};
const notesValidator = () => {
  return [body("content").notEmpty().withMessage("Content is required")];
};

export {
  userRegisterValidator,
  userLoginValidator,
  userForgetPasswordValidator,
  userResetForgottenPasswordValidator,
  userCurrentPasswordChangeValidator,
  projectValidator,
  addMemberTotheProjectValidator,
  createTaskValidator,
  updateTaskvalidator,
  notesValidator,
};
