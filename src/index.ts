import express from "express";
import authRoute from "./routes/auth.route";

const app = express();
app.use(express.json());

app.get("/", (req, res) => {
    res.send("Hello World!");
});

app.use("/auth", authRoute);

app.listen(3000, () => {
    console.log("Server started on port 3000");
});