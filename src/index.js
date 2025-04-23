import app from "./app.js";
import ConnectDB from "./db/index.js";
import dotenv from "dotenv";

dotenv.config({
    path: "./.env",
})

const PORT = process.env.PORT ?? 8000;

ConnectDB()
.then(()=>{
    app.listen(PORT , () => console.log(`servr is up and running fine on port ${PORT}`))
})
.catch((err=>{
    console.error( "Mongodb connection error" , err);
    process.exit(1);
}))