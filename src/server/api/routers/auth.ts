import { z } from "zod";
import { createTRPCRouter, publicProcedure } from "../trpc";
import { db } from "~/server/db";
import bcrypt from "bcryptjs";

export const authRouter = createTRPCRouter({
  register: publicProcedure
    .input(
      z.object({
        email: z.string().email(),
        password: z.string().min(6),
        name: z.string().optional(),
      })
    )
    .mutation(async ({ input }) => {
      const { email, password, name } = input;
      const existingUser = await db.user.findUnique({ where: { email } });
      if (existingUser) {
        throw new Error("Email already in use");
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = await db.user.create({
        data: {
          email,
          name: name ?? email,
          hashedPassword,
        },
      });
      return { id: user.id, email: user.email, name: user.name };
    }),
    login: publicProcedure.input( 
      z.object({
        email: z.string().email(),
        password: z.string().min(6),
      })
    ).mutation(async ({ input }) => {
      const { email, password } = input;
      const user = await db.user.findUnique({ where: { email } });
      if (!user) {
        throw new Error("No user found");
      }
      const isValid = await bcrypt.compare(password, user.hashedPassword);
      if (!isValid) {
        throw new Error("Invalid password");
      }
      return { id: user.id, email: user.email, name: user.name };
    }),
});
