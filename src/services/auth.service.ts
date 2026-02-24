import { AppError } from "../middleware/error-handler";
import UserRepository from "../repositories/user.repository";
import { LoginData, RegisterData } from "../schema/auth.schema";
import bcrypt from "bcrypt";

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

        return user;
    }
}

export default AuthService;