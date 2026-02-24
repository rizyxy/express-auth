import { Request, Response } from "express"
import { RegisterSchema } from "../schema/auth.schema";
import AuthService from "../services/auth.service";

const AuthController = {
    async register(req: Request, res: Response) {
        const registerData = RegisterSchema.safeParse(req.body);

        if (!registerData.success) {
            return res.status(400).json({ error: registerData.error.issues });
        }

        await AuthService.register(registerData.data);

        return res.status(201).json({ message: "User registered successfully" });
    }
}

export default AuthController;