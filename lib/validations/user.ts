import { z } from "zod"

// =============================================================================
// BASE VALIDATION SCHEMAS (Reusable primitives)
// =============================================================================

// Password validation with comprehensive security rules
const passwordSchema = z
  .string()
  .min(8, "Password must be at least 8 characters")
  .max(128, "Password must not exceed 128 characters")
  .regex(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
    "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character"
  )

// Email validation with security checks
const emailSchema = z
  .string()
  .email("Invalid email format")
  .max(254, "Email must not exceed 254 characters")
  .refine(
    (email) => {
      const localPart = email.split('@')[0]
      return localPart && localPart.length <= 64
    },
    "Email local part must not exceed 64 characters"
  )
  .refine(
    (email) => !email.includes('..'),
    "Email cannot contain consecutive dots"
  )
  .transform((email) => email.toLowerCase().trim())

// Phone validation with international support
const phoneSchema = z
  .string()
  .transform((val) => {
    // 1️⃣ Remove all characters except digits and +
    let cleaned = val.replace(/[^0-9+]/g, "");

    // 2️⃣ If + is not at the start → remove it everywhere
    if (cleaned.includes("+") && !cleaned.startsWith("+")) {
      cleaned = cleaned.replace(/\+/g, "");
    }

    // 3️⃣ If multiple +, keep only the first if at start
    cleaned = cleaned.replace(/(?!^)\+/g, "");

    return cleaned;
  })
  .refine((val) => {
    // ❌ Disallow +0
    if (/^\+0/.test(val)) return false;

    // ✅ Allow + followed by 1–9, or digits only (can start with 0)
    return /^(\+[1-9][0-9]{6,14}|[0-9]{7,15})$/.test(val);
  }, {
    message:
      "Invalid phone number. Must be 7–15 digits, may start with + but not +0 or contain special characters.",
  })
  .optional();

// Name validation with proper character support
const nameSchema = z
  .string()
  .min(2, "Name must be at least 2 characters")
  .max(100, "Name must not exceed 100 characters")
  .regex(
    /^[a-zA-Z\u00C0-\u017F\s\-\'\.]+$/,
    "Name can only contain letters, spaces, hyphens, apostrophes, and periods"
  )
  .transform((name) => name.trim().replace(/\s+/g, ' '))

// MongoDB ObjectId validation
const objectIdSchema = z
  .string()
  .regex(/^[0-9a-fA-F]{24}$/, "Invalid ObjectId format")
  .transform((id) => id.trim())

// URL validation with optional empty string
const urlSchema = z
  .string()
  .url("Invalid URL format")
  .or(z.literal(""))
  .optional()

// Status enums
const userStatusSchema = z.enum(["active", "inactive", "deleted", "suspended"])
const themeSchema = z.enum(["light", "dark", "system"])

// =============================================================================
// NESTED OBJECT SCHEMAS
// =============================================================================

// Address schema (nested object)
const addressSchema = z.object({
  street: z.string().max(200, "Street must not exceed 200 characters").optional(),
  city: z.string().max(100, "City must not exceed 100 characters").optional(),
  state: z.string().max(100, "State must not exceed 100 characters").optional(),
  country: z.string().max(100, "Country must not exceed 100 characters").optional(),
  zipCode: z.string().max(20, "ZIP code must not exceed 20 characters").optional(),
}).optional()

// Social links schema
const socialLinksSchema = z.array(z.object({
  linkName: z.string().min(1, "Social media platform name is required").max(50, "Platform name must not exceed 50 characters"),
  linkUrl: urlSchema,
})).optional()



// Emergency contact schema
const emergencyContactSchema = z.object({
  name: z.string().max(100, "Emergency contact name must not exceed 100 characters").optional(),
  phone: phoneSchema,
  relationship: z.string().max(50, "Relationship must not exceed 50 characters").optional(),
}).optional()

// Metadata schema
const metadataSchema = z.object({
  createdBy: z.string().optional(),
  updatedBy: z.string().optional(),
  notes: z.string().max(1000, "Notes must not exceed 1000 characters").optional(),
  tags: z.array(z.string().trim()).optional(),
}).optional()

// =============================================================================
// MAIN VALIDATION SCHEMAS (For API endpoints)
// =============================================================================

// Base user schema (common fields)
const baseUserSchema = z.object({
  name: nameSchema,
  email: emailSchema,
  phone: phoneSchema,
  department: objectIdSchema,
  position: z.string().max(100, "Position must not exceed 100 characters").optional(),
  status: userStatusSchema.default("active"),
  permissions: z.array(z.string().trim()).default([]),
  avatar: urlSchema,
  address: addressSchema,
  socialLinks: socialLinksSchema,
  metadata: metadataSchema,
  emergencyContact: emergencyContactSchema,
  isClient: z.boolean().default(false).optional(),
})

// Create user schema (for POST /api/users)
export const createUserSchema = baseUserSchema.extend({
  password: passwordSchema,
  role: objectIdSchema,
  bio: z.string().max(1000, "Bio must not exceed 1000 characters").optional(),
}).transform((data) => {
  // Transform bio to metadata.notes for backend consistency
  const transformed = { ...data }
  if (data.bio && !transformed.metadata) {
    transformed.metadata = { notes: data.bio }
  } else if (data.bio && transformed.metadata) {
    transformed.metadata.notes = data.bio
  }
  delete transformed.bio
  return transformed
})

// Update user schema (for PUT /api/users/[id])
export const updateUserSchema = baseUserSchema.partial().extend({
  _id: objectIdSchema.optional(),
  role: z.union([z.literal(""), objectIdSchema]).optional().transform(val => val === "" ? undefined : val),
  department: z.union([z.literal(""), objectIdSchema]).optional().transform(val => val === "" ? undefined : val),
  emailVerified: z.boolean().optional(),
  phoneVerified: z.boolean().optional(),
  twoFactorEnabled: z.boolean().optional(),
}).transform((data) => {
  // Remove undefined fields to prevent overwriting with undefined
  const cleaned: any = {}
  Object.entries(data).forEach(([key, value]) => {
    if (value !== undefined) {
      cleaned[key] = value
    }
  })
  return cleaned
})

// =============================================================================
// FRONTEND FORM SCHEMAS (Flat structure for React Hook Form)
// =============================================================================

// Create user form schema (with nested address structure for frontend forms)
export const createUserFormSchema = z.object({
  // Basic info
  name: nameSchema,
  email: emailSchema,
  password: passwordSchema,
  phone: z.string().optional(),
  department: z.string().min(1, "Department is required"),
  role: z.string().min(1, "Role is required"),
  position: z.string().optional(),
  status: userStatusSchema.default("active"),
  bio: z.string().max(1000).optional(),
  
  // Address (nested structure)
  address: addressSchema.optional(),
})

// Update user form schema (with nested structures for frontend forms)
export const updateUserFormSchema = z.object({
  // Basic info
  name: nameSchema.optional(),
  email: emailSchema.optional(),
  phone: z.string().optional(),
  department: z.string().optional(),
  role: z.string().optional(),
  position: z.string().optional(),
  status: userStatusSchema.optional(),
  bio: z.string().max(1000).optional(),

  // Address (nested structure)
  address: addressSchema.optional(),

  // Emergency contact (nested structure)
  emergencyContact: emergencyContactSchema.optional(),

}).transform((data) => {
  // Transform form data to API structure
  const transformed: any = { ...data }

  // Handle bio to metadata transformation
  if (data.bio) {
    if (!transformed.metadata) transformed.metadata = {}
    transformed.metadata.notes = data.bio
    delete transformed.bio
  }

  return transformed
})

// =============================================================================
// QUERY AND UTILITY SCHEMAS
// =============================================================================

// Query parameters validation for GET /api/users
export const userQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(10),
  search: z.string().trim().default(""),
  role: z.string().optional(),
  status: z.string().optional(), // Change this line - remove enum validation here
  department: z.string().optional(),
  sortBy: z.enum([
    "name", "email", "role", "status", "department",
    "position", "createdAt", "updatedAt", "lastLogin"
  ]).default("createdAt"),
  sortOrder: z.enum(["asc", "desc"]).default("desc"),
}).transform((data) => ({
  ...data,
  search: data.search || undefined,
  role: data.role && data.role !== "all" && data.role !== "" ? data.role : undefined,
  // Add proper handling for status - only validate non-empty values
  status: data.status && data.status !== "all" && data.status !== "" &&
    ["active", "inactive", "suspended"].includes(data.status) ? data.status : undefined,
  department: data.department && data.department !== "all" && data.department !== "" ? data.department : undefined,
}))

// Password change schema
export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, "Current password is required"),
  newPassword: passwordSchema,
  confirmPassword: z.string(),
}).refine(
  (data) => data.newPassword === data.confirmPassword,
  { message: "Passwords do not match", path: ["confirmPassword"] }
)

// Bulk operations schema
export const bulkUserUpdateSchema = z.object({
  userIds: z.array(objectIdSchema).min(1, "At least one user ID is required"),
  updates: z.object({
    status: userStatusSchema.optional(),
    department: objectIdSchema.optional(),
    role: objectIdSchema.optional(),
  }).refine(
    (data) => Object.keys(data).length > 0,
    "At least one update field is required"
  ),
})

// =============================================================================
// TYPE EXPORTS
// =============================================================================

export type CreateUserData = z.infer<typeof createUserSchema>
export type UpdateUserData = z.infer<typeof updateUserSchema>
export type CreateUserFormData = z.infer<typeof createUserFormSchema>
export type UpdateUserFormData = z.infer<typeof updateUserFormSchema>
export type UserQueryParams = z.infer<typeof userQuerySchema>
export type ChangePasswordData = z.infer<typeof changePasswordSchema>
export type BulkUserUpdateData = z.infer<typeof bulkUserUpdateSchema>

// Individual schema exports for reuse
export {
  passwordSchema,
  emailSchema,
  phoneSchema,
  nameSchema,
  objectIdSchema,
  userStatusSchema,
  themeSchema,
  addressSchema,
  socialLinksSchema,
  emergencyContactSchema,
  metadataSchema,
}

// =============================================================================
// VALIDATION HELPERS
// =============================================================================

export const validateObjectId = (id: string): boolean => {
  return objectIdSchema.safeParse(id).success
}

export const validateEmail = (email: string): boolean => {
  return emailSchema.safeParse(email).success
}

export const validatePhone = (phone: string): boolean => {
  return phoneSchema.safeParse(phone).success
}

export const validatePassword = (password: string): boolean => {
  return passwordSchema.safeParse(password).success
}

// Transform frontend form data to backend API format
export const transformFormToApi = (formData: any) => {
  return updateUserFormSchema.parse(formData)
}

// Transform backend API data to frontend form format
export const transformApiToForm = (apiData: any) => {
  const transformed: any = { ...apiData }

  // Keep address nested
  if (apiData.address) {
    transformed.address = {
      street: apiData.address.street || "",
      city: apiData.address.city || "",
      state: apiData.address.state || "",
      country: apiData.address.country || "",
      zipCode: apiData.address.zipCode || "",
    }
  }

  // Keep emergency contact nested
  if (apiData.emergencyContact) {
    transformed.emergencyContact = {
      name: apiData.emergencyContact.name || "",
      phone: apiData.emergencyContact.phone || "",
      relationship: apiData.emergencyContact.relationship || "",
    }
  }


  // Handle bio from metadata
  if (apiData.metadata?.notes) {
    transformed.bio = apiData.metadata.notes
  }

  return transformed
}