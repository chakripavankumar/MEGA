import { ApiResponce } from "../utils/api-responce";
const HealthCheck = (req,res) => {
     res.status(200).json( new ApiResponce(200,{ message : "Server is running"}))
}

export {HealthCheck}