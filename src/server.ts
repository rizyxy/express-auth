import express from "express";
import { PrismaClient } from "./generated/prisma";
import bcrypt, { hash } from "bcrypt";
import * as jwt from "jsonwebtoken";
import { expressjwt, Request as JWTRequest } from "express-jwt";    

require("dotenv").config();

const app = express();
app.use(express.json());

const prisma = new PrismaClient();

const port = 3000;

app.get('/', (_, res) => {
    res.send("Express Auth with JWT Example");
});

app.post('/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name) {
            return res.status(400).json({
                error: "Name cannot be empty"
            });
        }

        if (!email) {
            return res.status(400).json({
                error: "Email cannot be empty"
            });
        }

        if (!password) {
            return res.status(400).json({
                error: "Password cannot be empty"
            });
        }

        const hashedPassword = bcrypt.hashSync(password, 10);

        const user = await prisma.user.create({
            data: {
                id: crypto.randomUUID(),
                name: name,
                email: email,
                password: hashedPassword
            }
        });

        res.json({
            message: "User created",
            user: user
        });
    } catch (error) {
        res.status(500).json(error);
    } finally {
        prisma.$disconnect();
    }
});

app.post('/login', async (req, res) => {
    try {
        const {email, password} = req.body;

        if (!email) {
            return res.status(400).json({
                error: "Email cannot be empty"
            });
        }

        if (!password) {
            return res.status(400).json({
                error: "Password cannot be empty"
            });
        }

        const user = await prisma.user.findFirstOrThrow({
            where: {
                email: email
            }
        });

        if (!user) {
            return res.status(400).json({
                error: "No user with the corresponding email found"
            });
        }

        if (bcrypt.compareSync(password, user.password)) {
            const payload = {
                'id': user.id
            }

            if (!process.env.JWT_SECRET) {
                return res.status(500).json({ error: "JWT Error" });
            }

            const token = jwt.sign(payload, process.env.JWT_SECRET);

            return res.json({
                "token": token
            });
        }

        res.status(400).json({
            error: "Invalid credential"
        });
    } catch (error) {
        res.status(500).json(error);
    } finally {
        prisma.$disconnect();
    }
});

app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
});
