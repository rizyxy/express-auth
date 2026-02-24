import { prisma } from "../lib/prisma";

const UserRepository = {
    async create({ email, password }: { email: string, password: string }) {
        return await prisma.user.create({ data: { email, password } });
    },

    async findByEmail(email: string) {
        return await prisma.user.findFirstOrThrow({ where: { email } });
    }
}

export default UserRepository;