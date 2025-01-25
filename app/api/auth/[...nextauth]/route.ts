import NextAuth from "next-auth";
import GithubProvider from "next-auth/providers/github";
import GoogleProvider from "next-auth/providers/google";
import CredentialsProvider from "next-auth/providers/credentials";
import bcrypt from "bcryptjs";
import User from "@/models/User";
import connect from "@/utils/db";

// Correctly initializing NextAuth
const authHandler = NextAuth({
  providers: [
    CredentialsProvider({
      id: "credentials",
      name: "Credentials",
      credentials: {
        email: { label: "Email", type: "text" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        await connect();
        try {
          const user = await User.findOne({ email: credentials?.email });
          if (user) {
            const isPasswordCorrect = await bcrypt.compare(
              credentials!.password,
              user!.password
            );
            if (isPasswordCorrect) {
              return user;
            }
          }
        } catch (error: unknown) {
          if (error instanceof Error) {
            throw new Error(error?.message);
          } else {
            throw new Error("Some internal server error");
          }
        }
        return null;
      },
    }),
    GithubProvider({
      clientId: process.env.GITHUB_ID ?? "",
      clientSecret: process.env.GITHUB_SECRET ?? "",
    }),
    GoogleProvider({
      clientId: process.env.GOOGLE_ID ?? "",
      clientSecret: process.env.GOOGLE_SECRET ?? "",
    }),
  ],
  callbacks: {
    async signIn({ user, account }) {
      await connect();
      if (account?.provider === "credentials") {
        return true;
      }
      if (account?.provider === "github" || account?.provider === "google") {
        try {
          const existingUser = await User.findOne({ email: user.email });
          if (!existingUser) {
            const newUser = new User({ email: user.email });
            await newUser.save();
          }
          return true;
        } catch (err: unknown) {
          return false;
        }
      }
      return false;
    },
  },
});

// Correct export structure
export { authHandler as GET, authHandler as POST };
