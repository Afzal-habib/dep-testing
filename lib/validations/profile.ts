import { z } from "zod"

// =============================================================================
// BASE VALIDATION SCHEMAS (Reusable primitives)
// =============================================================================

// MongoDB ObjectId validation
const objectIdSchema = z
  .string()
  .regex(/^[0-9a-fA-F]{24}$/, "Invalid ObjectId format")
  .transform((id) => id.trim())

// Name validation with transformation
const nameSchema = z
  .string()
  .min(2, "Name must be at least 2 characters")
  .max(100, "Name must not exceed 100 characters")
  .regex(
    /^[a-zA-Z][a-zA-Z0-9\s\-_']*$/,
    "Name must start with letter and contain only letters, numbers, spaces, hyphens, underscores, and apostrophes"
  )
  .transform((name) => name.trim().replace(/\s+/g, ' '))

// Phone validation
const phoneSchema = z
  .string()
  .regex(/^[\+]?[1-9][\d]{0,15}$/, "Please enter a valid phone number")
  .optional()
  .or(z.literal(""))

// Position validation
const positionSchema = z
  .string()
  .max(100, "Position must not exceed 100 characters")
  .optional()
  .or(z.literal(""))

// Avatar URL validation
const avatarSchema = z
  .string()
  .url("Invalid avatar URL")
  .optional()
  .or(z.literal(""))

// Theme validation
const themeSchema = z.enum(["light", "dark", "system"])

// Password validation
const passwordSchema = z
  .string()
  .min(8, "Password must be at least 8 characters")
  .max(128, "Password must not exceed 128 characters")
  .regex(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/,
    "Password must contain at least one lowercase letter, one uppercase letter, and one number"
  )

// URL validation for social links
const urlSchema = z
  .string()
  .url("Invalid URL format")
  .optional()
  .or(z.literal(""))

// Address schema
const addressSchema = z.object({
  street: z.string().max(200, "Street must not exceed 200 characters").optional().or(z.literal("")),
  city: z.string().max(100, "City must not exceed 100 characters").optional().or(z.literal("")),
  state: z.string().max(100, "State must not exceed 100 characters").optional().or(z.literal("")),
  country: z.string().max(100, "Country must not exceed 100 characters").optional().or(z.literal("")),
  zipCode: z.string().max(20, "Zip code must not exceed 20 characters").optional().or(z.literal("")),
})

// Social links schema
const socialLinksSchema = z.object({
  linkedin: urlSchema,
  twitter: urlSchema,
  github: urlSchema,
}).optional()



// =============================================================================
// MAIN VALIDATION SCHEMAS
// =============================================================================

// Base profile schema (shared fields)
const baseProfileSchema = z.object({
  name: nameSchema,
  phone: phoneSchema,
  position: positionSchema,
  avatar: avatarSchema,
  address: addressSchema.optional(),
  socialLinks: socialLinksSchema.optional(),
})

// Update profile schema
export const updateProfileSchema = baseProfileSchema.partial().extend({
  name: nameSchema.optional(),
}).transform((data) => {
  // Clean up empty strings and null values
  const cleanData = { ...data }
  
  // Clean address
  if (cleanData.address) {
    const cleanAddress = Object.fromEntries(
      Object.entries(cleanData.address).filter(([_, value]) => value !== "" && value !== null)
    )
    cleanData.address = Object.keys(cleanAddress).length > 0 ? cleanAddress : undefined
  }
  
  // Clean social links
  if (cleanData.socialLinks) {
    const cleanSocialLinks = Object.fromEntries(
      Object.entries(cleanData.socialLinks).filter(([_, value]) => value !== "" && value !== null)
    )
    cleanData.socialLinks = Object.keys(cleanSocialLinks).length > 0 ? cleanSocialLinks : undefined
  }
  
  
  return cleanData
})

// Change password schema
export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, "Current password is required"),
  newPassword: passwordSchema,
  confirmPassword: z.string().min(1, "Please confirm your password"),
}).refine((data) => data.newPassword === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
})

// Profile form schema (for frontend forms)
export const profileFormSchema = z.object({
  name: nameSchema,
  phone: z.string().optional(),
  position: z.string().optional(),
  avatar: z.string().optional(),
  // Address fields
  street: z.string().optional(),
  city: z.string().optional(),
  state: z.string().optional(),
  country: z.string().optional(),
  zipCode: z.string().optional(),
  // Social links
  linkedin: z.string().optional(),
  twitter: z.string().optional(),
  github: z.string().optional(),
}).transform((data) => {
  // Transform flat form data to nested structure
  return {
    name: data.name,
    phone: data.phone || "",
    position: data.position || "",
    avatar: data.avatar || "",
    address: {
      street: data.street || "",
      city: data.city || "",
      state: data.state || "",
      country: data.country || "",
      zipCode: data.zipCode || "",
    },
    socialLinks: {
      linkedin: data.linkedin || "",
      twitter: data.twitter || "",
      github: data.github || "",
    },
  }
})

// Password change form schema
export const passwordChangeFormSchema = changePasswordSchema

// Profile response schema (for API responses)
export const profileResponseSchema = z.object({
  id: z.string(),
  name: z.string(),
  email: z.string().email(),
  phone: z.string().optional(),
  position: z.string().optional(),
  avatar: z.string().optional(),
  status: z.enum(["active", "inactive", "suspended"]),
  department: z.object({
    _id: z.string(),
    name: z.string(),
  }).optional(),
  role: z.object({
    _id: z.string(),
    name: z.string(),
    displayName: z.string(),
  }).optional(),
  lastLogin: z.date().optional(),
  sessionDuration: z.number(),
  sessionStartTime: z.string(),
  address: addressSchema.optional(),
  socialLinks: socialLinksSchema.optional(),
  emailVerified: z.boolean(),
  phoneVerified: z.boolean(),
  twoFactorEnabled: z.boolean(),
  createdAt: z.date(),
  updatedAt: z.date(),
})

// =============================================================================
// TYPE EXPORTS
// =============================================================================

export type UpdateProfileData = z.infer<typeof updateProfileSchema>
export type ChangePasswordData = z.infer<typeof changePasswordSchema>
export type ProfileFormData = z.infer<typeof profileFormSchema>
export type PasswordChangeFormData = z.infer<typeof passwordChangeFormSchema>
export type ProfileResponse = z.infer<typeof profileResponseSchema>

// =============================================================================
// VALIDATION HELPERS
// =============================================================================

export const validateObjectId = (id: string): boolean => {
  return objectIdSchema.safeParse(id).success
}

export const validateProfileUpdate = (data: unknown): data is UpdateProfileData => {
  return updateProfileSchema.safeParse(data).success
}

export const validatePasswordChange = (data: unknown): data is ChangePasswordData => {
  return changePasswordSchema.safeParse(data).success
}

// =============================================================================
// CONSTANTS
// =============================================================================

export const THEME_OPTIONS = [
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
  { value: "system", label: "System" },
] as const

export const LANGUAGE_OPTIONS = [
  { value: "en", label: "English" },
  { value: "es", label: "Spanish" },
  { value: "fr", label: "French" },
  { value: "de", label: "German" },
] as const

export const TIMEZONE_OPTIONS = [
  { value: "UTC", label: "UTC" },
  { value: "America/New_York", label: "Eastern Time" },
  { value: "America/Chicago", label: "Central Time" },
  { value: "America/Denver", label: "Mountain Time" },
  { value: "America/Los_Angeles", label: "Pacific Time" },
  { value: "Europe/London", label: "London" },
  { value: "Europe/Paris", label: "Paris" },
  { value: "Asia/Tokyo", label: "Tokyo" },
  { value: "Asia/Shanghai", label: "Shanghai" },
] as const

export type ThemeOption = typeof THEME_OPTIONS[number]["value"]
export type LanguageOption = typeof LANGUAGE_OPTIONS[number]["value"]
export type TimezoneOption = typeof TIMEZONE_OPTIONS[number]["value"]