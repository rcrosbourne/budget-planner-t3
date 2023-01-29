import {z} from "zod";
import {hash} from "bcryptjs";
import {createTRPCRouter, publicProcedure} from "../trpc";

export const userRouter   = createTRPCRouter({
    register: publicProcedure
        .input(z.object({
            email: z.string().email({message: "Invalid email"}),
            name: z.string(),
            password: z.string(),
        }))
        .mutation(async ({input, ctx}) => {
            // validate password and passwordConfirm
            const newUserOutputSchema = z.object({
                email: z.string(),
                name: z.string(),
                id: z.string(),
            });
            const newUser = await ctx.prisma.user.create({
                data: {
                    email: input.email,
                    name: input.name,
                    password: await hash(input.password, 10),
                }
            });
            return newUserOutputSchema.parse(newUser);
        }),
});
