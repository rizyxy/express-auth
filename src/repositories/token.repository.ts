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
    }
}

export default TokenRepository;
