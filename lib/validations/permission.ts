import { z } from "zod"

// =============================================================================
// BASE VALIDATION SCHEMAS (Reusable primitives)
// =============================================================================

// MongoDB ObjectId validation
const objectIdSchema = z
    .string()
    .regex(/^[0-9a-fA-F]{24}$/, "Invalid ObjectId format")
    .transform((id) => id.trim())

// Resource validation (for system permissions)
const resourceSchema = z
    .string()
    .min(2, "Resource must be at least 2 characters")
    .max(50, "Resource must not exceed 50 characters")
    .regex(
        /^[a-z][a-z0-9_]*$/,
        "Resource must start with letter and contain only lowercase letters, numbers, and underscores"
    )
    .transform((val) => val.toLowerCase().trim())

// Action validation with comprehensive list
const actionSchema = z.enum([
    'create', 'read', 'update', 'delete',
    'assign', 'approve', 'reject',
    'export', 'import', 'archive',
    'clone', 'backup', 'restore',
    'schedule', 'purge', 'test',
    'manage', 'configure', 'audit'
])

// Condition validation
const conditionSchema = z.enum([
    'own', 'department', 'assigned', 'subordinates', 'all'
])

// Permission category validation
const permissionCategorySchema = z.enum([
    'user_management',
    'department_management',
    'role_management',
    'system_administration',
    'reporting',
    'data_management',
    'security',
    'integration',
    'custom'
])

// Status validation
const permissionStatusSchema = z.enum(['active', 'inactive', 'archived'])

// Display name validation
const displayNameSchema = z
    .string()
    .min(2, "Display name must be at least 2 characters")
    .max(100, "Display name must not exceed 100 characters")
    .transform((name) => name.trim().replace(/\s+/g, ' '))

// Description validation
const descriptionSchema = z
    .string()
    .max(500, "Description must not exceed 500 characters")
    .optional()
    .transform((desc) => desc?.trim() || undefined)

// Version validation
const versionSchema = z
    .string()
    .regex(/^\d+\.\d+\.\d+$/, "Version must be in format x.y.z")
    .default("1.0.0")

// =============================================================================
// NESTED OBJECT SCHEMAS
// =============================================================================

// Resource action schema (for system permissions)
const resourceActionSchema = z.object({
    action: actionSchema,
    description: z
        .string()
        .min(1, "Action description is required")
        .max(200, "Action description must not exceed 200 characters")
        .transform((desc) => desc.trim()),
    conditions: z
        .array(conditionSchema)
        .optional()
        .default([])
})

// Permission conditions schema (for role permissions)
const permissionConditionsSchema = z.object({
    own: z.boolean().optional().default(false),
    department: z.boolean().optional().default(false),
    assigned: z.boolean().optional().default(false),
    subordinates: z.boolean().optional().default(false),
}).optional()

// Permission metadata schema
const permissionMetadataSchema = z.object({
    createdBy: z.string().optional(),
    updatedBy: z.string().optional(),
    version: versionSchema.optional(),
    notes: z.string().max(1000, "Notes must not exceed 1000 characters").optional(),
    tags: z.array(z.string().max(50)).max(20).optional(),
}).optional()

// =============================================================================
// ROLE PERMISSION SCHEMAS
// =============================================================================

// Role permission schema (used in roles)
export const rolePermissionSchema = z.object({
    resource: resourceSchema,
    actions: z
        .array(actionSchema)
        .min(1, "At least one action must be specified")
        .max(15, "Cannot have more than 15 actions per permission"),
    conditions: permissionConditionsSchema,
})

// Role permissions array schema
export const rolePermissionsSchema = z
    .array(rolePermissionSchema)
    .min(1, "Role must have at least one permission")
    .max(50, "Role cannot have more than 50 permissions")

// =============================================================================
// SYSTEM PERMISSION SCHEMAS
// =============================================================================

// Base system permission schema
const baseSystemPermissionSchema = z.object({
    resource: resourceSchema,
    displayName: displayNameSchema,
    description: descriptionSchema,
    category: permissionCategorySchema,
    availableActions: z
        .array(resourceActionSchema)
        .min(1, "Resource must have at least one available action")
        .max(20, "Resource cannot have more than 20 actions"),
    isCore: z.boolean().default(false),
    status: permissionStatusSchema.default("active"),
    metadata: permissionMetadataSchema,
})

// Create system permission schema
export const createSystemPermissionSchema = baseSystemPermissionSchema

// Update system permission schema
export const updateSystemPermissionSchema = baseSystemPermissionSchema.partial().extend({
    _id: objectIdSchema.optional(),
}).transform((data) => {
    // Remove undefined fields
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

// System permission form schema (for creating/editing system permissions)
export const systemPermissionFormSchema = z.object({
    resource: z.string().min(2).max(50),
    displayName: displayNameSchema,
    description: z.string().max(500).optional(),
    category: z.string().min(1, "Category is required"),
    isCore: z.boolean().default(false),
    status: z.string().default("active"),

    // Available actions (flat structure for forms)
    actions: z.string().min(1, "At least one action is required"), // Comma-separated string

    // Metadata (flat for forms)
    notes: z.string().max(1000).optional(),
    tags: z.string().optional(), // Comma-separated string
}).transform((data) => {
    // Transform flat form data to nested API structure
    const transformed: any = {
        resource: data.resource.toLowerCase().trim(),
        displayName: data.displayName,
        description: data.description,
        category: data.category.toLowerCase(),
        isCore: data.isCore,
        status: data.status as 'active' | 'inactive' | 'archived',
    }

    // Transform actions string to availableActions array
    if (data.actions) {
        const actionsList = data.actions.split(',').map(a => a.trim()).filter(Boolean)
        transformed.availableActions = actionsList.map(action => ({
            action: action.toLowerCase(),
            description: `${action.charAt(0).toUpperCase() + action.slice(1)} ${data.displayName.toLowerCase()}`,
            conditions: []
        }))
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

// Role permission form schema (for permission selector components)
export const rolePermissionFormSchema = z.object({
    resource: z.string().min(1, "Resource is required"),
    actions: z.array(z.string()).min(1, "At least one action is required"),

    // Conditions (flat for forms)
    allowOwn: z.boolean().default(false),
    allowDepartment: z.boolean().default(false),
    allowAssigned: z.boolean().default(false),
    allowSubordinates: z.boolean().default(false),
    allowUnrestricted: z.boolean().default(false),
}).transform((data) => {
    // Transform to role permission format
    return {
        resource: data.resource.toLowerCase(),
        actions: data.actions.map(a => a.toLowerCase()),
        conditions: {
            own: data.allowOwn,
            department: data.allowDepartment,
            assigned: data.allowAssigned,
            subordinates: data.allowSubordinates,
            unrestricted: data.allowUnrestricted,
        }
    }
})

// Bulk permissions form schema (for role creation/editing)
export const bulkPermissionsFormSchema = z.object({
    permissions: z.array(rolePermissionFormSchema).min(1, "At least one permission is required"),
})

// =============================================================================
// QUERY AND UTILITY SCHEMAS
// =============================================================================

// System permission query schema
export const systemPermissionQuerySchema = z.object({
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(10),
    search: z.string().trim().default(""),
    category: z.string().optional(),
    resource: z.string().optional(),
    isCore: z.coerce.boolean().optional(),
    status: permissionStatusSchema.optional(),
    includeInactive: z.coerce.boolean().default(false),
    sortBy: z.enum([
        "resource", "displayName", "category", "isCore",
        "status", "createdAt", "updatedAt"
    ]).default("category"),
    sortOrder: z.enum(["asc", "desc"]).default("asc"),
}).transform((data) => ({
    ...data,
    search: data.search || undefined,
    category: data.category && data.category !== "all" ? data.category : undefined,
    resource: data.resource && data.resource !== "all" ? data.resource : undefined,
}))

// Permission check schema
export const permissionCheckSchema = z.object({
    userId: objectIdSchema.optional(),
    resource: resourceSchema,
    action: actionSchema,
    condition: conditionSchema.optional(),
    targetUserId: objectIdSchema.optional(),
    targetDepartmentId: objectIdSchema.optional(),
    context: z.record(z.any()).optional(), // Additional context data
})

// Role permission update schema
export const rolePermissionUpdateSchema = z.object({
    roleId: objectIdSchema,
    permissions: rolePermissionsSchema,
})

// Bulk permission operations
export const bulkPermissionOperationSchema = z.object({
    operation: z.enum(['assign', 'revoke', 'update']),
    roleIds: z.array(objectIdSchema).min(1, "At least one role ID is required"),
    permissions: rolePermissionsSchema.optional(),
    resource: resourceSchema.optional(),
    actions: z.array(actionSchema).optional(),
}).refine((data) => {
    if (data.operation === 'assign' || data.operation === 'update') {
        return data.permissions && data.permissions.length > 0
    }
    if (data.operation === 'revoke') {
        return data.resource || (data.permissions && data.permissions.length > 0)
    }
    return true
}, "Invalid operation parameters")

// =============================================================================
// RESPONSE SCHEMAS
// =============================================================================

// System permission response schema
export const systemPermissionResponseSchema = z.object({
    _id: z.string(),
    resource: z.string(),
    displayName: z.string(),
    description: z.string().optional(),
    category: permissionCategorySchema,
    availableActions: z.array(resourceActionSchema),
    isCore: z.boolean(),
    status: permissionStatusSchema,
    metadata: permissionMetadataSchema,
    createdAt: z.date(),
    updatedAt: z.date(),
})

// Role permission response schema
export const rolePermissionResponseSchema = z.object({
    resource: z.string(),
    actions: z.array(z.string()),
    conditions: permissionConditionsSchema,
})

// Permission validation response schema
export const permissionValidationResponseSchema = z.object({
    hasAccess: z.boolean(),
    resource: z.string(),
    action: z.string(),
    condition: z.string().optional(),
    reason: z.string().optional(),
    metadata: z.record(z.any()).optional(),
})

// =============================================================================
// TYPE EXPORTS
// =============================================================================

export type RolePermissionData = z.infer<typeof rolePermissionSchema>
export type RolePermissionsData = z.infer<typeof rolePermissionsSchema>
export type CreateSystemPermissionData = z.infer<typeof createSystemPermissionSchema>
export type UpdateSystemPermissionData = z.infer<typeof updateSystemPermissionSchema>
export type SystemPermissionFormData = z.infer<typeof systemPermissionFormSchema>
export type RolePermissionFormData = z.infer<typeof rolePermissionFormSchema>
export type BulkPermissionsFormData = z.infer<typeof bulkPermissionsFormSchema>
export type SystemPermissionQueryParams = z.infer<typeof systemPermissionQuerySchema>
export type PermissionCheckData = z.infer<typeof permissionCheckSchema>
export type RolePermissionUpdateData = z.infer<typeof rolePermissionUpdateSchema>
export type BulkPermissionOperationData = z.infer<typeof bulkPermissionOperationSchema>
export type SystemPermissionResponse = z.infer<typeof systemPermissionResponseSchema>
export type RolePermissionResponse = z.infer<typeof rolePermissionResponseSchema>
export type PermissionValidationResponse = z.infer<typeof permissionValidationResponseSchema>

// Individual schema exports for reuse
export {
    objectIdSchema,
    resourceSchema,
    actionSchema,
    conditionSchema,
    permissionCategorySchema,
    permissionStatusSchema,
    displayNameSchema,
    descriptionSchema,
    resourceActionSchema,
    permissionConditionsSchema,
    permissionMetadataSchema,
}

// =============================================================================
// VALIDATION HELPERS
// =============================================================================

export const validateResource = (resource: string): boolean => {
    return resourceSchema.safeParse(resource).success
}

export const validateAction = (action: string): boolean => {
    return actionSchema.safeParse(action).success
}

export const validateRolePermission = (permission: unknown): permission is RolePermissionData => {
    return rolePermissionSchema.safeParse(permission).success
}

export const validateSystemPermission = (permission: unknown): permission is CreateSystemPermissionData => {
    return createSystemPermissionSchema.safeParse(permission).success
}

export const validateObjectId = (id: string): boolean => {
    return objectIdSchema.safeParse(id).success
}

// Transform frontend form data to backend API format
export const transformSystemPermissionFormToApi = (formData: any) => {
    return systemPermissionFormSchema.parse(formData)
}

export const transformRolePermissionFormToApi = (formData: any) => {
    return rolePermissionFormSchema.parse(formData)
}

// Transform backend API data to frontend form format
export const transformSystemPermissionApiToForm = (apiData: any) => {
    const flattened: any = { ...apiData }

    // Flatten availableActions to actions string
    if (apiData.availableActions && Array.isArray(apiData.availableActions)) {
        flattened.actions = apiData.availableActions.map((a: any) => a.action).join(', ')
    }

    // Flatten metadata
    if (apiData.metadata) {
        flattened.notes = apiData.metadata.notes
        flattened.tags = apiData.metadata.tags ? apiData.metadata.tags.join(', ') : ''
    }

    return flattened
}

export const transformRolePermissionApiToForm = (apiData: any) => {
    const flattened: any = {
        resource: apiData.resource,
        actions: apiData.actions || [],
    }

    // Flatten conditions
    if (apiData.conditions) {
        flattened.allowOwn = apiData.conditions.own || false
        flattened.allowDepartment = apiData.conditions.department || false
        flattened.allowAssigned = apiData.conditions.assigned || false
        flattened.allowSubordinates = apiData.conditions.subordinates || false
        flattened.allowUnrestricted = apiData.conditions.unrestricted || false
    }

    return flattened
}

// =============================================================================
// CONSTANTS AND PATTERNS
// =============================================================================

export const PERMISSION_ACTIONS = [
    'create', 'read', 'update', 'delete',
    'assign', 'approve', 'reject',
    'export', 'import', 'archive',
    'clone', 'backup', 'restore',
    'schedule', 'purge', 'test',
    'manage', 'configure', 'audit'
] as const

export const PERMISSION_CONDITIONS = [
    'own', 'department', 'assigned', 'subordinates', 'all'
] as const

export const PERMISSION_CATEGORIES = [
    'user_management',
    'department_management',
    'role_management',
    'system_administration',
    'reporting',
    'data_management',
    'security',
    'integration',
    'custom'
] as const

export const PERMISSION_STATUS_TYPES = [
    'active', 'inactive', 'archived'
] as const

export type PermissionAction = typeof PERMISSION_ACTIONS[number]
export type PermissionCondition = typeof PERMISSION_CONDITIONS[number]
export type PermissionCategory = typeof PERMISSION_CATEGORIES[number]
export type PermissionStatus = typeof PERMISSION_STATUS_TYPES[number]

// Permission templates for common resources
export const SYSTEM_PERMISSION_TEMPLATES = {
    USERS: {
        resource: 'users',
        displayName: 'User Management',
        category: 'user_management',
        availableActions: [
            { action: 'create', description: 'Create new users' },
            { action: 'read', description: 'View user information' },
            { action: 'update', description: 'Modify user details' },
            { action: 'delete', description: 'Remove users' },
            { action: 'assign', description: 'Assign roles to users' },
        ]
    },
    ROLES: {
        resource: 'roles',
        displayName: 'Role Management',
        category: 'role_management',
        availableActions: [
            { action: 'create', description: 'Create new roles' },
            { action: 'read', description: 'View role information' },
            { action: 'update', description: 'Modify role details' },
            { action: 'delete', description: 'Remove roles' },
            { action: 'configure', description: 'Configure role permissions' },
        ]
    },
    DEPARTMENTS: {
        resource: 'departments',
        displayName: 'Department Management',
        category: 'department_management',
        availableActions: [
            { action: 'create', description: 'Create new departments' },
            { action: 'read', description: 'View department information' },
            { action: 'update', description: 'Modify department details' },
            { action: 'delete', description: 'Remove departments' },
            { action: 'manage', description: 'Manage department structure' },
        ]
    },
    SYSTEM: {
        resource: 'system',
        displayName: 'System Administration',
        category: 'system_administration',
        availableActions: [
            { action: 'configure', description: 'Configure system settings' },
            { action: 'audit', description: 'Access audit logs' },
            { action: 'backup', description: 'Create system backups' },
            { action: 'restore', description: 'Restore from backups' },
            { action: 'manage', description: 'Full system management' },
        ]
    },
} as const

// Common permission patterns
export const COMMON_PERMISSION_PATTERNS = {
    CRUD: ['create', 'read', 'update', 'delete'],
    READ_ONLY: ['read'],
    READ_WRITE: ['read', 'update'],
    MANAGER: ['create', 'read', 'update', 'assign'],
    ADMIN: ['create', 'read', 'update', 'delete', 'manage'],
    SUPER_ADMIN: ['create', 'read', 'update', 'delete', 'manage', 'configure', 'audit'],
} as const