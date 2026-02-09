import { z } from 'zod'

// Base constants for validation
export const DEPARTMENT_CONSTANTS = {
  NAME: {
    MIN_LENGTH: 2,
    MAX_LENGTH: 100,
  },
  DESCRIPTION: {
    MAX_LENGTH: 2000, // Increased to handle HTML content
  },
  CATEGORY: {
    VALUES: ['sales', 'support', 'it', 'management'] as const,
    DEFAULT: 'it' as const,
  },
  STATUS: {
    VALUES: ['active', 'inactive', 'deleted'] as const,
    DEFAULT: 'active' as const,
  },
  PAGINATION: {
    DEFAULT_PAGE: 1,
    DEFAULT_LIMIT: 10,
    MAX_LIMIT: 100,
    MIN_PAGE: 1,
  },
  SORT: {
    ALLOWED_FIELDS: ['name', 'status', 'createdAt', 'updatedAt'] as const,
    DEFAULT_FIELD: 'createdAt' as const,
    DEFAULT_ORDER: 'desc' as const,
  },
} as const

// Custom validation helpers
const createStringValidator = (config: { min?: number; max?: number; required?: boolean }) => {
  let validator = z.string()

  if (config.min) {
    validator = validator.min(config.min, `Must be at least ${config.min} characters`)
  }

  if (config.max) {
    validator = validator.max(config.max, `Cannot exceed ${config.max} characters`)
  }

  // Trim all strings
  const trimmedValidator = validator.transform((val) => val.trim())

  if (config.required === false) {
    return trimmedValidator.optional()
  }

  return trimmedValidator
}

// MongoDB ObjectId validation
export const objectIdSchema = z.string().regex(
  /^[0-9a-fA-F]{24}$/,
  'Invalid ID format'
)

// Base department schema (shared fields)
export const baseDepartmentSchema = z.object({
  name: createStringValidator({
    min: DEPARTMENT_CONSTANTS.NAME.MIN_LENGTH,
    max: DEPARTMENT_CONSTANTS.NAME.MAX_LENGTH,
    required: true,
  }).refine(
    (name) => name && name.length > 0,
    'Department name is required'
  ),
  category: z.enum(['sales', 'support', 'it', 'management'], {
    errorMap: () => ({ message: 'Category must be one of: sales, support, it, management' })
  }),

  description: z.string()
    .max(DEPARTMENT_CONSTANTS.DESCRIPTION.MAX_LENGTH, `Description cannot exceed ${DEPARTMENT_CONSTANTS.DESCRIPTION.MAX_LENGTH} characters`)
    .nullable()
    .optional()
    .transform((val) => {
      // Convert empty strings, null, and empty HTML to undefined
      if (!val || val.trim() === '' || val.trim() === '<p><br></p>') return undefined
      return val.trim()
    }),

  status: z.enum(DEPARTMENT_CONSTANTS.STATUS.VALUES, {
    errorMap: () => ({ message: 'Status must be either active or inactive' })
  }).default(DEPARTMENT_CONSTANTS.STATUS.DEFAULT),
})

// Create department schema
export const createDepartmentSchema = baseDepartmentSchema.strict()

// Update department schema - all fields optional for PATCH operations
export const updateDepartmentSchema = baseDepartmentSchema.partial().extend({
  // Allow isDeleted field only when restoring (setting to false)
  isDeleted: z.literal(false).optional(),
}).strict().refine(
  (data) => {
    // Ensure at least one field is provided for update
    const hasValidField = Object.values(data).some(value =>
      value !== undefined && value !== null && value !== ''
    )
    return hasValidField
  },
  {
    message: 'At least one field must be provided for update',
  }
)

// Department with ID schema (for responses)
export const departmentWithIdSchema = baseDepartmentSchema.extend({
  _id: objectIdSchema,
  createdAt: z.date().or(z.string().transform(str => new Date(str))),
  updatedAt: z.date().or(z.string().transform(str => new Date(str))),
})

// Department filters schema
export const departmentFiltersSchema = z.object({
  search: z.string().optional(),
  status: z.enum(['active', 'inactive', '']).optional(),
  category: z.enum(['sales', 'support', 'it', 'management', '']).optional(),
})

// Department sort schema
export const departmentSortSchema = z.object({
  field: z.enum(['name', 'status', 'createdAt', 'updatedAt', '_id']),
  direction: z.enum(['asc', 'desc']),
})

// Fetch departments params schema
export const fetchDepartmentsParamsSchema = z.object({
  page: z.number()
    .int('Page must be an integer')
    .min(DEPARTMENT_CONSTANTS.PAGINATION.MIN_PAGE, 'Page must be at least 1')
    .optional(),

  limit: z.number()
    .int('Limit must be an integer')
    .min(1, 'Limit must be at least 1')
    .max(DEPARTMENT_CONSTANTS.PAGINATION.MAX_LIMIT, `Limit cannot exceed ${DEPARTMENT_CONSTANTS.PAGINATION.MAX_LIMIT}`)
    .optional(),

  filters: departmentFiltersSchema.optional(),
  sort: departmentSortSchema.optional(),
})

// Query parameters schema (for URL/API query params - coerced from strings)
export const departmentQuerySchema = z.object({
  // Pagination
  page: z.coerce.number()
    .int('Page must be an integer')
    .min(DEPARTMENT_CONSTANTS.PAGINATION.MIN_PAGE, 'Page must be at least 1')
    .default(DEPARTMENT_CONSTANTS.PAGINATION.DEFAULT_PAGE),

  limit: z.coerce.number()
    .int('Limit must be an integer')
    .min(1, 'Limit must be at least 1')
    .max(DEPARTMENT_CONSTANTS.PAGINATION.MAX_LIMIT, `Limit cannot exceed ${DEPARTMENT_CONSTANTS.PAGINATION.MAX_LIMIT}`)
    .default(DEPARTMENT_CONSTANTS.PAGINATION.DEFAULT_LIMIT),

  // Search and filters
  search: z.string()
    .trim()
    .optional()
    .transform(val => val || undefined), // Convert empty string to undefined

  category: z.string()
    .trim()
    .optional()
    .transform(val => {
      if (!val || val === 'all') return ''
      return val
    })
    .refine(val => {
      if (val === '' || val === undefined) return true
      return DEPARTMENT_CONSTANTS.CATEGORY.VALUES.includes(val as any)
    }, 'Invalid category value'),
  status: z.string()
    .trim()
    .optional()
    .transform(val => {
      if (!val || val === 'all') return ''
      return val
    })
    .refine(val => {
      if (val === '' || val === undefined) return true
      return DEPARTMENT_CONSTANTS.STATUS.VALUES.includes(val as any)
    }, 'Invalid status value'),


  // Sorting
  sortBy: z.enum([...DEPARTMENT_CONSTANTS.SORT.ALLOWED_FIELDS])
    .default(DEPARTMENT_CONSTANTS.SORT.DEFAULT_FIELD),

  sortOrder: z.enum(['asc', 'desc'])
    .default(DEPARTMENT_CONSTANTS.SORT.DEFAULT_ORDER),

  // Additional filters
  includeInactive: z.coerce.boolean().optional().default(false),
})

// Department ID parameter schema
export const departmentIdSchema = z.object({
  id: objectIdSchema,
})

// Bulk operations schema
export const bulkDepartmentOperationSchema = z.object({
  operation: z.enum(['delete', 'activate', 'deactivate']),
  departmentIds: z.array(objectIdSchema).min(1, 'At least one department ID is required'),
})

// API Response schemas
export const departmentResponseSchema = z.object({
  success: z.boolean(),
  data: departmentWithIdSchema.optional(),
  message: z.string().optional(),
  error: z.string().optional(),
})

export const departmentsListResponseSchema = z.object({
  success: z.boolean(),
  data: z.object({
    departments: z.array(departmentWithIdSchema),
    pagination: z.object({
      page: z.number(),
      limit: z.number(),
      total: z.number(),
      pages: z.number(),
    }),
    stats: z.object({
      totalDepartments: z.number(),
      activeDepartments: z.number(),
      inactiveDepartments: z.number(),
    }).optional(),
  }).optional(),
  message: z.string().optional(),
  error: z.string().optional(),
})

// Validation helper functions
export const validateDepartment = {
  create: (data: unknown) => createDepartmentSchema.safeParse(data),
  update: (data: unknown) => updateDepartmentSchema.safeParse(data),
  query: (data: unknown) => departmentQuerySchema.safeParse(data),
  fetchParams: (data: unknown) => fetchDepartmentsParamsSchema.safeParse(data),
  filters: (data: unknown) => departmentFiltersSchema.safeParse(data),
  sort: (data: unknown) => departmentSortSchema.safeParse(data),
  id: (data: unknown) => departmentIdSchema.safeParse(data),
  bulk: (data: unknown) => bulkDepartmentOperationSchema.safeParse(data),
}

// Validation error formatter
export const formatValidationErrors = (errors: z.ZodError) => {
  return errors.errors.map(error => ({
    field: error.path.join('.'),
    message: error.message,
    code: error.code,
  }))
}

// Custom validation rules
export const departmentValidationRules = {
  // Check if name is unique (to be used in backend with database access)
  isNameUnique: async (name: string, excludeId?: string) => {
    // This would be implemented in the backend with database access
    // Frontend can use this interface for consistent validation
    return true // Placeholder
  },

  // Sanitize department name
  sanitizeName: (name: string): string => {
    return name
      .trim()
      .replace(/\s+/g, ' ') // Replace multiple spaces with single space
      .replace(/[^\w\s-]/g, '') // Remove special characters except hyphens
  },

  // Generate department slug
  generateSlug: (name: string): string => {
    return name
      .toLowerCase()
      .trim()
      .replace(/\s+/g, '-')
      .replace(/[^\w-]/g, '')
  },
}

// Environment-specific validation
export const getValidationConfig = () => {
  const isServer = typeof window === 'undefined'

  return {
    strictMode: isServer, // More strict validation on server
    sanitizeInputs: true,
    logValidationErrors: isServer,
  }
}

// Middleware helpers for Next.js API routes
export const validateRequestBody = (schema: z.ZodSchema) => {
  return (data: unknown) => {
    const result = schema.safeParse(data)
    if (!result.success) {
      throw new Error(`Validation failed: ${formatValidationErrors(result.error).map(e => e.message).join(', ')}`)
    }
    return result.data
  }
}

export const validateRequestQuery = (query: Record<string, string | string[]>) => {
  // Convert Next.js query object to proper format
  const processedQuery: Record<string, any> = {}

  Object.entries(query).forEach(([key, value]) => {
    if (Array.isArray(value)) {
      processedQuery[key] = value[0] // Take first value if array
    } else {
      processedQuery[key] = value
    }
  })

  return departmentQuerySchema.parse(processedQuery)
}

// ============================
// Type exports (z.infer)
// ============================

// Base types
export type Department = z.infer<typeof departmentWithIdSchema>
export type CreateDepartmentData = z.infer<typeof createDepartmentSchema>
export type UpdateDepartmentData = z.infer<typeof updateDepartmentSchema>
export type DepartmentIdParams = z.infer<typeof departmentIdSchema>
export type BulkDepartmentOperation = z.infer<typeof bulkDepartmentOperationSchema>
export type DepartmentResponse = z.infer<typeof departmentResponseSchema>
export type DepartmentsListResponse = z.infer<typeof departmentsListResponseSchema>
