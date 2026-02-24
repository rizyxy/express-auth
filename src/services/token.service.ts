import { User } from "../../generated/prisma/client";
import jwt, { JwtPayload } from "jsonwebtoken";
import { AppError } from "../middleware/error-handler";
import TokenRepository from "../repositories/token.repository";

export enum TokenType {
    ACCESS = 'access',
    REFRESH = 'refresh'
}

const TokenService = {
    async issueAccessAndRefreshToken(user: User): Promise<{ accessToken: string, refreshToken: string }> {
        if (!process.env.JWT_SECRET) {
            throw new AppError("Token service error", 500);
        }

        const accessToken = jwt.sign({ userId: user.id, tokenType: TokenType.ACCESS }, process.env.JWT_SECRET, {
            expiresIn: '15m'
        });

        const refreshToken = jwt.sign({ userId: user.id, tokenType: TokenType.REFRESH }, process.env.JWT_SECRET, {
            expiresIn: '7d'
        });

        try {
            await TokenRepository.create({ token: refreshToken, userId: user.id });
        } catch (error) {
            throw new AppError("Error creating token", 500);
        }

        return { accessToken, refreshToken };
    }
}

export default TokenService;