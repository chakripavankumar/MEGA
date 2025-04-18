import mongoose from "mongoose";

const ConnectDB = async () => {
      try {
         await mongoose.connect(process.env.MONGODB_URL)
      } catch (error) {
        console.error("Mongodb connection failed", error);
        process.exit(1);
      }
}
export default ConnectDB;