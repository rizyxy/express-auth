import { Request, Response } from "express"
import { LoginSchema, RegisterSchema } from "../schema/auth.schema";
import AuthService from "../services/auth.service";

const AuthController = {
    async register(req: Request, res: Response) {
        const registerData = RegisterSchema.safeParse(req.body);

        if (!registerData.success) {
            return res.status(400).json({ error: registerData.error.issues });
        }

        await AuthService.register(registerData.data);

        return res.status(201).json({ message: "User registered successfully" });
    },

    async login(req: Request, res: Response) {
        const loginData = LoginSchema.safeParse(req.body);

        if (!loginData.success) {
            return res.status(400).json({ error: loginData.error.issues });
        }

        await AuthService.login(loginData.data);

        return res.status(200).json({ message: "User logged in successfully" });
    }
}

export default AuthController;