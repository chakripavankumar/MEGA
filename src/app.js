import express from "express"
import cookieParser from "cookie-parser";
import healthCheckRouter from "./routes/healthcheck.route.js"

const app = express();

app.use(cookieParser());
app.use(express.json());



app.use("/api/v1/healthcheck", healthCheckRouter)


export default app;