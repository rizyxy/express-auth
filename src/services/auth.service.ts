import UserRepository from "../repositories/user.repository";
import { RegisterData } from "../schema/auth.schema";
import bcrypt from "bcrypt";

const AuthService = {
    async register(data: RegisterData) {
        const hashedPassword = await bcrypt.hash(data.password, 10);

        const user = await UserRepository.create({
            email: data.email,
            password: hashedPassword
        })

        return user;
    }
}

export default AuthService;