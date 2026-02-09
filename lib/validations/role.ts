import { z } from "zod"

// =============================================================================
// BASE VALIDATION SCHEMAS (Reusable primitives)
// =============================================================================

// MongoDB ObjectId validation
const objectIdSchema = z
  .string()
  .regex(/^[0-9a-fA-F]{24}$/, "Invalid ObjectId format")
  .transform((id) => id.trim())

// Role name validation with transformation
const roleNameSchema = z
  .string()
  .min(2, "Role name must be at least 2 characters")
  .max(100, "Role name must not exceed 100 characters")
  .regex(
    /^[a-zA-Z][a-zA-Z0-9\s\-_]*$/,
    "Role name must start with letter and contain only letters, numbers, spaces, hyphens, and underscores"
  )
  .transform((name) => name.trim().replace(/\s+/g, ' '))

// Display name validation
const displayNameSchema = z
  .string()
  .min(2, "Display name must be at least 2 characters")
  .max(150, "Display name must not exceed 150 characters")
  .transform((name) => name.trim().replace(/\s+/g, ' '))

// Description validation
const descriptionSchema = z
  .string()
  .max(500, "Description must not exceed 500 characters")
  .optional()
  .transform((desc) => desc?.trim() || undefined)

// Hierarchy level validation
const hierarchyLevelSchema = z
  .coerce
  .number()
  .min(1, "Hierarchy level must be at least 1")
  .max(10, "Hierarchy level cannot exceed 10")
  .default(1)

// Status validation
const roleStatusSchema = z.enum(["active", "inactive", "archived", "deleted"])

// Actions enum with comprehensive list
const actionSchema = z.enum([
  'create', 'read', 'update', 'delete',
  'assign', 'approve', 'reject',
  'export', 'import', 'archive',
  'clone', 'backup', 'restore',
  'schedule', 'purge', 'test',
  'manage', 'configure', 'audit'
])

// Resource validation
const resourceSchema = z
  .string()
  .min(2, "Resource must be at least 2 characters")
  .max(50, "Resource must not exceed 50 characters")
  .regex(
    /^[a-z][a-z0-9_]*$/,
    "Resource must start with letter and contain only lowercase letters, numbers, and underscores"
  )
  .transform((val) => val.toLowerCase().trim())

// =============================================================================
// NESTED OBJECT SCHEMAS
// =============================================================================

// Permission conditions schema
const permissionConditionsSchema = z.object({
  own: z.boolean().optional(),
  department: z.boolean().optional(),
  assigned: z.boolean().optional(),
  subordinates: z.boolean().optional(),
}).optional()

// Permission schema
const permissionSchema = z.object({
  resource: resourceSchema,
  actions: z
    .array(actionSchema)
    .min(1, "At least one action must be specified")
    .max(15, "Cannot have more than 15 actions per permission"),
  conditions: permissionConditionsSchema,
})

// Validity period schema
const validityPeriodSchema = z
  .object({
    startDate: z.string().datetime().optional(),
    endDate: z.string().datetime().optional(),
  })
  .optional()
  .refine((period) => {
    if (period?.startDate && period?.endDate) {
      return new Date(period.startDate) < new Date(period.endDate)
    }
    return true
  }, "Start date must be before end date")

// Metadata schema
const roleMetadataSchema = z.object({
  createdBy: z.string().optional(),
  updatedBy: z.string().optional(),
  notes: z.string().max(1000, "Notes must not exceed 1000 characters").optional(),
  tags: z.array(z.string().max(50)).max(20, "Cannot have more than 20 tags").optional(),
}).optional()

// Role statistics (for responses)
const roleStatisticsSchema = z.object({
  totalUsers: z.number().default(0),
  activeUsers: z.number().default(0),
  inactiveUsers: z.number().default(0),
  utilizationRate: z.number().nullable().optional(),
}).optional()

// Department reference schema
const departmentReferenceSchema = z.union([
  objectIdSchema,
  z.object({
    _id: objectIdSchema,
    name: z.string(),
    description: z.string().optional(),
    status: z.string().optional(),
  })
])

// =============================================================================
// MAIN VALIDATION SCHEMAS (For API endpoints)
// =============================================================================

// Base role schema (common fields)
const baseRoleSchema = z.object({
  name: roleNameSchema,
  displayName: displayNameSchema,
  description: descriptionSchema,
  department: objectIdSchema,
  hierarchyLevel: hierarchyLevelSchema,
  isSystemRole: z.boolean().default(false),
  status: roleStatusSchema.default("active"),
  maxUsers: z
    .coerce
    .number()
    .min(1, "Max users must be at least 1")
    .max(1000, "Max users cannot exceed 1000")
    .optional()
    .default(1),
  validityPeriod: validityPeriodSchema,
  metadata: roleMetadataSchema,
})

// Create role schema (for POST /api/roles)
export const createRoleSchema = baseRoleSchema.extend({
  permissions: z
    .array(permissionSchema)
    // .min(1, "Role must have at least one permission")
    // .max(50, "Role cannot have more than 50 permissions")
    .default([]),
}).transform((data) => {
  // Auto-generate name from displayName if not provided
  if (!data.name && data.displayName) {
    const generatedName = data.displayName
      .toLowerCase()
      .replace(/[^a-zA-Z0-9\s\-_]/g, '')
      .replace(/\s+/g, '_')
      .substring(0, 50)

    return { ...data, name: generatedName }
  }
  return data
})

// Update role schema (for PUT /api/roles/[id])
export const updateRoleSchema = baseRoleSchema.partial().extend({
  _id: objectIdSchema.optional(),
  isDeleted: z.literal(false).optional(),
  permissions: z
    .array(permissionSchema)
    // .min(1, "Role must have at least one permission")
    // .max(50, "Role cannot have more than 50 permissions")
    .optional(),
}).transform((data) => {
  // Remove undefined fields to prevent overwriting with undefined
  const cleaned: any = {}
  Object.entries(data).forEach(([key, value]) => {
    if (value !== undefined && value !== null) {
      cleaned[key] = value
    }
  })
  return cleaned
})

// =============================================================================
// FRONTEND FORM SCHEMAS (Flat structure for React Hook Form)
// =============================================================================

// Create role form schema (for frontend forms)
export const createRoleFormSchema = z.object({
  // Basic info
  name: z.string().optional(), // Will be auto-generated
  displayName: displayNameSchema,
  description: z.string().max(500).optional(),
  department: z.string().min(1, "Department is required"),
  hierarchyLevel: z.coerce.number().min(1).max(10).default(1),
  maxUsers: z.coerce.number().min(1).max(1000).optional(),

  // Validity period (flat for forms)
  validityStartDate: z.string().optional(),
  validityEndDate: z.string().optional(),

  // Metadata (flat for forms)
  notes: z.string().max(1000).optional(),
  tags: z.string().optional(), // Comma-separated string
}).transform((data) => {
  // Transform flat form data to nested API structure
  const transformed: any = { ...data }

  // Handle validity period transformation
  if (data.validityStartDate || data.validityEndDate) {
    transformed.validityPeriod = {
      startDate: data.validityStartDate || undefined,
      endDate: data.validityEndDate || undefined,
    }
    delete transformed.validityStartDate
    delete transformed.validityEndDate
  }

  // Handle metadata transformation
  if (data.notes || data.tags) {
    transformed.metadata = {
      notes: data.notes,
      tags: data.tags ? data.tags.split(',').map(tag => tag.trim()).filter(Boolean) : undefined,
    }
    delete transformed.notes
    delete transformed.tags
  }

  // Auto-generate name if not provided
  if (!transformed.name && data.displayName) {
    transformed.name = data.displayName
      .toLowerCase()
      .replace(/[^a-zA-Z0-9\s\-_]/g, '')
      .replace(/\s+/g, '_')
      .substring(0, 50)
  }

  return transformed
})

// Update role form schema (for frontend forms)
export const updateRoleFormSchema = z.object({
  // Basic info
  name: roleNameSchema.optional(),
  displayName: displayNameSchema.optional(),
  description: z.string().max(500).optional(),
  department: z.string().optional(),
  hierarchyLevel: z.number().min(1).max(10).optional(),
  maxUsers: z.number().min(1).max(1000).optional(),
  status: roleStatusSchema.optional(),

  // Validity period (flat for forms)
  validityStartDate: z.string().optional(),
  validityEndDate: z.string().optional(),

  // Metadata (flat for forms)
  notes: z.string().max(1000).optional(),
  tags: z.string().optional(), // Comma-separated string
}).transform((data) => {
  // Transform flat form data to nested API structure
  const transformed: any = {}

  // Copy basic fields
  Object.entries(data).forEach(([key, value]) => {
    if (value !== undefined && !['validityStartDate', 'validityEndDate', 'notes', 'tags'].includes(key)) {
      transformed[key] = value
    }
  })

  // Handle validity period transformation
  if (data.validityStartDate || data.validityEndDate) {
    transformed.validityPeriod = {
      startDate: data.validityStartDate || undefined,
      endDate: data.validityEndDate || undefined,
    }
  }

  // Handle metadata transformation
  if (data.notes || data.tags) {
    transformed.metadata = {
      notes: data.notes,
      tags: data.tags ? data.tags.split(',').map(tag => tag.trim()).filter(Boolean) : undefined,
    }
  }

  return transformed
})

// =============================================================================
// QUERY AND UTILITY SCHEMAS
// =============================================================================

// Query parameters validation for GET /api/roles
export const roleQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(10),
  search: z.string().trim().default(""),
  department: z.string().optional(),
  hierarchyLevel: z.coerce.number().int().min(1).max(10).optional(),
  isSystemRole: z.coerce.boolean().optional(),
  status: z.string().optional(),
  sortBy: z.enum([
    "name", "displayName", "department", "hierarchyLevel",
    "status", "createdAt", "updatedAt"
  ]).default("createdAt"),
  sortOrder: z.enum(["asc", "desc"]).default("desc"),
}).transform((data) => ({
  ...data,
  search: data.search || undefined,
  department: data.department && data.department !== "all" ? data.department : undefined,
  status: data.status && data.status !== "all" ? data.status : undefined,
}))

// Role assignment schema
export const roleAssignmentSchema = z.object({
  userId: objectIdSchema,
  roleId: objectIdSchema,
  effectiveDate: z.string().datetime().optional(),
  expiryDate: z.string().datetime().optional(),
  notes: z.string().max(500).optional(),
}).refine((data) => {
  if (data.effectiveDate && data.expiryDate) {
    return new Date(data.effectiveDate) < new Date(data.expiryDate)
  }
  return true
}, "Effective date must be before expiry date")

// Permission check schema
export const rolePermissionCheckSchema = z.object({
  resource: resourceSchema,
  action: actionSchema,
  condition: z.enum(['own', 'department', 'assigned', 'subordinates']).optional(),
  targetUserId: objectIdSchema.optional(),
  targetDepartmentId: objectIdSchema.optional(),
})

// Bulk operations schema
export const bulkRoleUpdateSchema = z.object({
  roleIds: z.array(objectIdSchema).min(1, "At least one role ID is required"),
  updates: z.object({
    status: roleStatusSchema.optional(),
    department: objectIdSchema.optional(),
    hierarchyLevel: hierarchyLevelSchema.optional(),
  }).refine(
    (data) => Object.keys(data).length > 0,
    "At least one update field is required"
  ),
})

// =============================================================================
// RESPONSE SCHEMAS
// =============================================================================

// Role response schema (for API responses)
export const roleResponseSchema = z.object({
  _id: z.string(),
  name: z.string(),
  displayName: z.string(),
  description: z.string().optional(),
  department: departmentReferenceSchema,
  permissions: z.array(permissionSchema),
  hierarchyLevel: z.number(),
  isSystemRole: z.boolean(),
  status: roleStatusSchema,
  maxUsers: z.number().optional(),
  validityPeriod: validityPeriodSchema,
  metadata: roleMetadataSchema,
  createdAt: z.date(),
  updatedAt: z.date(),
  // Virtual/computed fields
  statistics: roleStatisticsSchema,
  userCount: z.number().optional(),
})

// Permission response schema
export const permissionResponseSchema = z.object({
  resource: z.string(),
  actions: z.array(z.string()),
  conditions: permissionConditionsSchema,
})

// =============================================================================
// TYPE EXPORTS
// =============================================================================

export type CreateRoleData = z.infer<typeof createRoleSchema>
export type UpdateRoleData = z.infer<typeof updateRoleSchema>
export type CreateRoleFormData = z.infer<typeof createRoleFormSchema>
export type UpdateRoleFormData = z.infer<typeof updateRoleFormSchema>
export type RoleQueryParams = z.infer<typeof roleQuerySchema>
export type RoleAssignmentData = z.infer<typeof roleAssignmentSchema>
export type RolePermissionCheck = z.infer<typeof rolePermissionCheckSchema>
export type BulkRoleUpdateData = z.infer<typeof bulkRoleUpdateSchema>
export type RoleResponse = z.infer<typeof roleResponseSchema>
export type PermissionData = z.infer<typeof permissionSchema>
export type PermissionResponse = z.infer<typeof permissionResponseSchema>

// Individual schema exports for reuse
export {
  objectIdSchema,
  roleNameSchema,
  displayNameSchema,
  descriptionSchema,
  hierarchyLevelSchema,
  roleStatusSchema,
  actionSchema,
  resourceSchema,
  permissionSchema,
  permissionConditionsSchema,
  validityPeriodSchema,
  roleMetadataSchema,
  departmentReferenceSchema,
}

// =============================================================================
// VALIDATION HELPERS
// =============================================================================

export const validateObjectId = (id: string): boolean => {
  return objectIdSchema.safeParse(id).success
}

export const validatePermission = (permission: unknown): permission is PermissionData => {
  return permissionSchema.safeParse(permission).success
}

export const validateRole = (role: unknown): role is CreateRoleData => {
  return createRoleSchema.safeParse(role).success
}

export const validateRoleUpdate = (role: unknown): role is UpdateRoleData => {
  return updateRoleSchema.safeParse(role).success
}

// Transform frontend form data to backend API format
export const transformRoleFormToApi = (formData: any) => {
  return createRoleFormSchema.parse(formData)
}

// Transform backend API data to frontend form format
export const transformRoleApiToForm = (apiData: any) => {
  const flattened: any = { ...apiData }

  // Flatten validity period
  if (apiData.validityPeriod) {
    flattened.validityStartDate = apiData.validityPeriod.startDate
    flattened.validityEndDate = apiData.validityPeriod.endDate
  }

  // Flatten metadata
  if (apiData.metadata) {
    flattened.notes = apiData.metadata.notes
    flattened.tags = apiData.metadata.tags ? apiData.metadata.tags.join(', ') : ''
  }

  // Handle department reference
  if (typeof apiData.department === 'object' && apiData.department._id) {
    flattened.department = apiData.department._id
  }

  return flattened
}

// =============================================================================
// CONSTANTS AND PATTERNS
// =============================================================================

export const RESOURCE_PATTERNS = {
  CAMEL_CASE: /^[a-z][a-zA-Z0-9]*$/,
  SNAKE_CASE: /^[a-z][a-z0-9_]*$/,
  KEBAB_CASE: /^[a-z][a-z0-9\-]*$/,
}

export const ACTION_TYPES = [
  'create', 'read', 'update', 'delete',
  'assign', 'approve', 'reject',
  'export', 'import', 'archive',
  'clone', 'backup', 'restore',
  'schedule', 'purge', 'test',
  'manage', 'configure', 'audit'
] as const

export const CONDITION_TYPES = [
  'own', 'department', 'assigned', 'subordinates'
] as const

export const ROLE_STATUS_TYPES = [
  'active', 'inactive', 'archived'
] as const

export const HIERARCHY_LEVELS = {
  SUPER_ADMIN: 10,
  ADMIN: 9,
  MANAGER: 7,
  SUPERVISOR: 5,
  SENIOR: 3,
  REGULAR: 1,
} as const

export type ActionType = typeof ACTION_TYPES[number]
export type ConditionType = typeof CONDITION_TYPES[number]
export type RoleStatusType = typeof ROLE_STATUS_TYPES[number]

// Permission templates for common roles
export const PERMISSION_TEMPLATES = {
  SUPER_ADMIN: [
    { resource: 'users', actions: ['create', 'read', 'update', 'delete', 'manage'] },
    { resource: 'roles', actions: ['create', 'read', 'update', 'delete', 'manage'] },
    { resource: 'departments', actions: ['create', 'read', 'update', 'delete', 'manage'] },
    { resource: 'system', actions: ['configure', 'audit', 'backup', 'restore'] },
  ],
  ADMIN: [
    { resource: 'users', actions: ['create', 'read', 'update', 'delete'] },
    { resource: 'roles', actions: ['read', 'update'] },
    { resource: 'departments', actions: ['read', 'update'] },
    { resource: 'reports', actions: ['read', 'create', 'export'] },
  ],
  MANAGER: [
    { resource: 'users', actions: ['read', 'update'], conditions: { department: true } },
    { resource: 'reports', actions: ['read', 'create'] },
    { resource: 'projects', actions: ['create', 'read', 'update', 'assign'] },
  ],
  USER: [
    { resource: 'profile', actions: ['read', 'update'], conditions: { own: true } },
    { resource: 'projects', actions: ['read'], conditions: { assigned: true } },
  ],
} as const