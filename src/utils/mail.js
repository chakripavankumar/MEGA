import Mailgen from "mailgen";
import nodemailer from "nodemailer";
import { ApiError } from "./api-error.js";

export const sendEmail = async (options) => {
  if (!options.mailgenContent) {
    throw new ApiError(500, "Missing email content (mailgenContent)");
  }
  const mailGenerator = new Mailgen({
    theme: "default",
    product: {
      name: "Task Manager",
      link: "https://taskmanager.app",
    },
  });
  const emailText = mailGenerator.generatePlaintext(options.mailgenContent);
  const emailHtml = mailGenerator.generate(options.mailgenContent);
  const transporter = nodemailer.createTransport({
    host: process.env.MAILTRAP_SMTP_HOST,
    port: process.env.MAILTRAP_SMTP_PORT,
    auth: {
      user: process.env.MAILTRAP_SMTP_USER,
      pass: process.env.MAILTRAP_SMTP_PASS,
    },
  });
  const mail = {
    from: "mail.taskmanager@example.com",
    to: options.email,
    subject: options.subject,
    text: emailText,
    html: emailHtml,
  };
  try {
    await transporter.sendMail(mail);
  } catch (error) {
    console.error(
      "Email service failed silently. Make sure you have provided your MAILTRAP credentials in the .env file",
    );
    throw new ApiError("email could be sent", 500);
  }
};
export const emailVerificationMailgenContent = (username, verificationUrl) => {
  return {
    body: {
      name: username,
      intro:
        "Welcome to Task Manager! We're very excited to have you on board.",
      action: {
        instructions:
          "To get started with Task Manager, please verify your email address by clicking the button below:",
        button: {
          color: "#22BC66",
          text: "Verify your email",
          link: verificationUrl,
        },
      },
      outro: "If you did not create an account, no further action is required.",
    },
  };
};

export const forgotPasswordMailgenContent = (username, passwordResetUrl) => {
  return {
    body: {
      name: username,
      intro: "You have requested to reset your password.",
      action: {
        instructions:
          "To reset your password click on the following button or link:",
        button: {
          color: "#22BC66", // Optional action button color
          text: "Reset password",
          link: passwordResetUrl,
        },
      },
      outro:
        "If you did not request a password reset, please ignore this email.",
    },
  };
};
