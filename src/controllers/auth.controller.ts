import { CookieOptions, Request, Response } from "express"
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

        const { accessToken, refreshToken } = await AuthService.login(loginData.data);

        const isProd = process.env.NODE_ENV === "production";
        const commonOptions: CookieOptions = {
            httpOnly: true,
            secure: isProd,
            sameSite: "strict",
            path: "/",
        };

        res.cookie("x-refresh-token", `Bearer ${refreshToken}`, {
            ...commonOptions,
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        res.cookie("x-access-token", `Bearer ${accessToken}`, commonOptions);

        return res.status(200).json({
            message: "Logged in successfully",
        });
    }
}

export default AuthController;