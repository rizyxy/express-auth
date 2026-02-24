import UserRepository from "../repositories/user.repository";
import { LoginData, RegisterData } from "../schema/auth.schema";
import bcrypt from "bcrypt";

const AuthService = {
    async register(data: RegisterData) {
        const hashedPassword = await bcrypt.hash(data.password, 10);

        const user = await UserRepository.create({
            email: data.email,
            password: hashedPassword
        })

        return user;
    },

    async login(data: LoginData) {
        const user = await UserRepository.findByEmail(data.email);

        if (!user) {
            throw new Error("User not found");
        }

        const isPasswordValid = await bcrypt.compare(data.password, user.password);

        if (!isPasswordValid) {
            throw new Error("Invalid password");
        }

        return user;
    }
}

export default AuthService;