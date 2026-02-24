import { Request, Response } from "express"
import { LoginSchema, RegisterSchema } from "../schema/auth.schema";
import AuthService from "../services/auth.service";
import { AppError } from "../middleware/error-handler";

const AuthController = {
    async register(req: Request, res: Response) {
        const registerData = RegisterSchema.safeParse(req.body);

        if (!registerData.success) {
            throw new AppError("Invalid request", 400);
        }

        await AuthService.register(registerData.data);

        return res.status(201).json({ message: "User registered successfully" });
    },

    async login(req: Request, res: Response) {
        const loginData = LoginSchema.safeParse(req.body);

        if (!loginData.success) {
            throw new AppError("Invalid request", 400);
        }

        await AuthService.login(loginData.data);

        return res.status(200).json({ message: "User logged in successfully" });
    }
}

export default AuthController;