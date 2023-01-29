import NextAuth, {type NextAuthOptions} from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
// Prisma adapter for NextAuth, optional and can be removed
import {PrismaAdapter} from "@next-auth/prisma-adapter";
import jwt from "jsonwebtoken";

import {env} from "../../../env/server.mjs";
import {prisma} from "../../../server/db";
import type {JWT} from "next-auth/jwt";
import {compare} from "bcryptjs";

export const authOptions: NextAuthOptions = {
    pages: {
        signIn: "/auth/signin",
    },
    session: {
        strategy: "jwt",
    },
    jwt: {
        encode({token}) {
            return jwt.sign(token, env.NEXTAUTH_SECRET);
        },
        decode({token}) {
            return jwt.verify(token, env.NEXTAUTH_SECRET) as JWT;
        },
    },
    // Include user.id on session
    callbacks: {
        session({session, token}) {
            if (session.user) {
                session.user.id = token.sub ?? "";
            }
            return session;
        },
    },
    // Configure one or more authentication providers
    adapter: PrismaAdapter(prisma),
    providers: [
        CredentialsProvider({
            name: "Credentials",
            type: "credentials",
            id: "credentials",
            credentials: {
                email: {label: "Email", type: "text", placeholder: "jsmith@gmail.com"},
                password: {label: "Password", type: "password"},
            },
            authorize: async (credentials) => {
                if (!credentials) {
                    return null;
                }
                const user = await prisma.user.findUnique({
                    where: {
                        email: credentials.email,
                    }
                });
                if (!user || !user.password) {
                    throw new Error("Invalid email/password");
                }
                const isValid = await compare(credentials.password, user.password);
                if (!isValid) {
                    throw new Error("Invalid email/password");
                }
                return user;
            },
        }),
    ],
};
export default NextAuth(authOptions);
