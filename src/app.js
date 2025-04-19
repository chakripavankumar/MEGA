import express from "express"

const app = express();

// import all the routes here 

import router from  "./routes/healthcheck.route"

app.use("/api/v1/healthcheck", router)


export default app;