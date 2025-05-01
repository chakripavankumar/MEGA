import jwt from "jsonwebtoken";

export const generateAccessToken = (userId) =>
  jwt.sign({ id: userId }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "15m",
  });

export const generateRefreshToken = (userId) =>
  jwt.sign({ id: userId }, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "7d",
  });

export const verifyToken = (token, secret) =>
  jwt.verify(token, secret);