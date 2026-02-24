import express from "express";
import authRoute from "./routes/auth.route";
import { errorHandlerMiddleware } from "./middleware/error-handler";

const app = express();
app.use(express.json());

app.get("/", (req, res) => {
    res.send("Hello World!");
});

app.use("/auth", authRoute);

// DO NOT MOVE THIS MIDDLEWARE TO ANYWHERE ELSE
app.use(errorHandlerMiddleware);

app.listen(3000, () => {
    console.log("Server started on port 3000");
});