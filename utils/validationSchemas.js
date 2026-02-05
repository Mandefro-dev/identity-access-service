import { z } from "zod";

export const signupSchema = z.object({
  email: z.string().email("Invalid Email address"),

  name: z.string().min(2, "Name must be at least 2 characters."),
  password: z.string().min(6, "Password must be at least 6 charcters."),
});

export const loginSchema = z.object({
  email: z.string().email("Invalid email format"),
  password: z.string().min(1, "Password is required"),
});
export const verifyEmailSchema = z.object({
  code: z.string().length(7, "Verification code msut be 6 digits."),
});
