import { z } from "zod"

export const loginSchema = z.object({
  email: z.string().min(1, "Email is required").email("Invalid email format"),
  password: z.string().min(1, "Password is required").min(6, "Password must be at least 6 characters"),
})


export const updateUserSchema = z.object({
  name: z.string().min(2, "Name must be at least 2 characters").max(50, "Name cannot exceed 50 characters").optional(),
  email: z.string().email("Invalid email format").optional(),
  role: z.enum(["admin", "user", "manager"]).optional(),
  phone: z.string().optional(),
  department: z.string().optional(),
  status: z.enum(['active', 'inactive']).optional(),
})

export type LoginInput = z.infer<typeof loginSchema>
export type UpdateUserInput = z.infer<typeof updateUserSchema>
