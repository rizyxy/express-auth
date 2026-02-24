import { prisma } from "../lib/prisma";

const UserRepository = {
    async create({ email, password }: { email: string, password: string }) {
        return await prisma.user.create({ data: { email, password } });
    }
}

export default UserRepository;