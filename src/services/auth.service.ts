import { AppError } from "../middleware/error-handler";
import UserRepository from "../repositories/user.repository";
import { LoginData, RegisterData } from "../schema/auth.schema";
import bcrypt from "bcrypt";
import TokenService, { TokenType } from "./token.service";

const AuthService = {
    async register(data: RegisterData) {
        const hashedPassword = await bcrypt.hash(data.password, 10);

        const existingUser = await UserRepository.findByEmail(data.email);

        if (existingUser) {
            throw new AppError("Email already registered", 400);
        }

        const user = await UserRepository.create({
            email: data.email,
            password: hashedPassword
        })

        return user;
    },

    async login(data: LoginData) {
        const user = await UserRepository.findByEmail(data.email);

        if (!user) {
            throw new AppError("Invalid email or password", 404);
        }

        const isPasswordValid = await bcrypt.compare(data.password, user.password);

        if (!isPasswordValid) {
            throw new AppError("Invalid email or password", 404);
        }

        const { accessToken, refreshToken } = await TokenService.issueAccessAndRefreshToken(user);

        return { accessToken, refreshToken };
    },

    async refreshToken(token: string) {
        const tokenData = TokenService.verifyToken(token);

        if (tokenData.tokenType !== TokenType.REFRESH) {
            throw new AppError(`Invalid token`, 401);
        }

        const user = await UserRepository.findByEmail(tokenData.email);

        if (!user) {
            throw new AppError("User not found", 404);
        }

        const { accessToken, refreshToken } = await TokenService.issueAccessAndRefreshToken(user);

        return { accessToken, refreshToken };
    }
}

export default AuthService;