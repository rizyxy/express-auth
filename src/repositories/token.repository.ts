import { TokenStatus } from "../../generated/prisma/enums";
import { prisma } from "../lib/prisma";

const TokenRepository = {
    async create({ token, userId }: { token: string, userId: string }) {
        // Set token expiration date to 7 days from now
        const expiresAt = new Date(new Date().setDate(new Date().getDate() + 7));

        return await prisma.refreshToken.create({
            data: {
                token,
                userId,
                expiresAt
            }
        });
    },

    async findByToken(token: string) {
        return await prisma.refreshToken.findFirstOrThrow({
            where: {
                token
            },
            include: {
                user: true
            }
        });
    },

    async deleteByUserId(userId: string) {
        return await prisma.refreshToken.deleteMany({
            where: {
                userId
            }
        });
    },

    async updateStatusByToken(token: string, status: TokenStatus) {
        return await prisma.refreshToken.update({
            where: {
                token
            },
            data: {
                status
            }
        });
    }
}

export default TokenRepository;
