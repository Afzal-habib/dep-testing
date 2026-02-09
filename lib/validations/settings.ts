import { z } from "zod"
import { VALID_THEME_VARIANTS } from "@/lib/constants/theme-variants"

// Theme variant validation using centralized theme variants
export const themeVariantSchema = z.enum(VALID_THEME_VARIANTS as [string, ...string[]], {
  errorMap: () => ({ 
    message: `Invalid theme variant. Must be one of: ${VALID_THEME_VARIANTS.join(', ')}`
  })
})

// Setting validation schemas
export const createSettingSchema = z.object({
  key: z.string()
    .min(1, "Setting key is required")
    .max(100, "Setting key must be 100 characters or less")
    .regex(/^[a-z0-9_]+$/, "Setting key must contain only lowercase letters, numbers, and underscores"),
  
  value: z.any().refine(val => val !== undefined, {
    message: "Setting value is required"
  }),
  
  description: z.string()
    .max(500, "Description must be 500 characters or less")
    .optional(),
  
  category: z.enum(['appearance', 'security', 'notifications', 'system', 'general'])
    .default('general'),
  
  isPublic: z.boolean()
    .default(false)
})

export const updateSettingSchema = z.object({
  key: z.string()
    .min(1, "Setting key is required")
    .max(100, "Setting key must be 100 characters or less"),
  
  value: z.any().refine(val => val !== undefined, {
    message: "Setting value is required"
  }),
  
  description: z.string()
    .max(500, "Description must be 500 characters or less")
    .optional(),
  
  category: z.enum(['appearance', 'security', 'notifications', 'system', 'general'])
    .optional(),
  
  isPublic: z.boolean()
    .optional()
})

export const updateThemeSchema = z.object({
  theme_variant: themeVariantSchema.optional(),
  theme: themeVariantSchema.optional()
}).refine(data => data.theme_variant || data.theme, {
  message: "Either theme_variant or theme must be provided"
})

// Settings query validation
export const settingsQuerySchema = z.object({
  category: z.enum(['appearance', 'security', 'notifications', 'system', 'general'])
    .optional(),
  
  includePrivate: z.string()
    .transform(val => val === 'true')
    .optional()
})

// Batch settings creation
export const batchCreateSettingsSchema = z.array(createSettingSchema)
  .min(1, "At least one setting is required")
  .max(50, "Cannot create more than 50 settings at once")

// Export types
export type CreateSettingData = z.infer<typeof createSettingSchema>
export type UpdateSettingData = z.infer<typeof updateSettingSchema>
export type UpdateThemeData = z.infer<typeof updateThemeSchema>
export type SettingsQueryData = z.infer<typeof settingsQuerySchema>
export type BatchCreateSettingsData = z.infer<typeof batchCreateSettingsSchema>
export type ThemeVariant = z.infer<typeof themeVariantSchema>

// Predefined setting validation by key
export const settingValidators = {
  theme_variant: themeVariantSchema,
  
  system_name: z.string()
    .min(1, "System name is required")
    .max(100, "System name must be 100 characters or less"),
  
  maintenance_mode: z.boolean(),
  
  max_login_attempts: z.number()
    .int("Must be a whole number")
    .min(1, "Must be at least 1")
    .max(100, "Must be 100 or less"),
  
  session_timeout: z.number()
    .int("Must be a whole number")
    .min(300, "Must be at least 5 minutes (300 seconds)")
    .max(86400, "Must be 24 hours or less (86400 seconds)"),
  
  password_min_length: z.number()
    .int("Must be a whole number")
    .min(4, "Must be at least 4 characters")
    .max(128, "Must be 128 characters or less"),
  
  enable_email_notifications: z.boolean(),
  
  backup_frequency: z.enum(['daily', 'weekly', 'monthly']),
  
  backup_directory: z.string()
    .min(1, "Backup directory is required")
    .max(500, "Backup directory path is too long"),
  
  backup_retention_days: z.number()
    .int("Must be a whole number")
    .min(1, "Must keep backups for at least 1 day")
    .max(365, "Cannot keep backups for more than 365 days"),
  
  auto_backup_enabled: z.boolean()
}

// Validate setting value based on key
export function validateSettingValue(key: string, value: any) {
  const validator = settingValidators[key as keyof typeof settingValidators]
  if (validator) {
    return validator.safeParse(value)
  }
  // If no specific validator, just check it's not undefined
  return z.any().refine(val => val !== undefined).safeParse(value)
}