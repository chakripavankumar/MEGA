import { ApiResponce } from "../utils/api-responce";
const healthCheck = (req,res) => {
     res.status(200).json( new ApiResponce(200,{ message : "Server is running"}))
}

export {healthCheck}