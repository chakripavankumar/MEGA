import express from "express";
import cookieParser from "cookie-parser";
import healthCheckRouter from "./routes/healthcheck.route.js";
import authRouter from "./routes/auth.route.js";

const app = express();

app.use(cookieParser());
app.use(express.json());

app.use("/api/v1/healthcheck", healthCheckRouter);
app.use("/api/v1/auth", authRouter);

export default app;
