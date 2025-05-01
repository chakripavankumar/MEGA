import app from "./app.js";
import ConnectDB from "./db/index.js";
import dotenv from "dotenv";
import cors from "cors";

app.use(cors());
const PORT = process.env.PORT ?? 3000;
dotenv.config({
  path: "./.env",
});

ConnectDB()
  .then(() => {
    app.listen(PORT, () =>
      console.log(`servr is up and running fine on port ${PORT}`),
    );
  })
  .catch((err) => {
    console.error("Mongodb connection error", err);
    process.exit(1);
  });
