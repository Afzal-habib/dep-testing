import { z } from 'zod'

// Constants for validation
export const PROJECT_CONSTANTS = {
  NAME: { MIN_LENGTH: 2, MAX_LENGTH: 200 },
  DESCRIPTION: { MAX_LENGTH: 1000 },
  REQUIREMENTS: { MAX_LENGTH: 200 },
  CUSTOMER_SERVICES: { MAX_LENGTH: 200 },
  TIMELINE: { MAX_LENGTH: 500 },
  PROJECT_TYPE: { MAX_LENGTH: 100 },
  STATUS: {
    VALUES: ['pending', 'active', 'completed', 'approved', 'inactive', 'deleted'] as const,
    DEFAULT: 'pending' as const
  },
  PRIORITY: {
    VALUES: ['low', 'medium', 'high', 'urgent'] as const,
    DEFAULT: 'medium' as const
  },
  BUDGET_BREAKDOWN: {
    DEVELOPMENT: { MIN: 0 },
    DESIGN: { MIN: 0 },
    TESTING: { MIN: 0 },
    DEPLOYMENT: { MIN: 0 },
    MAINTENANCE: { MIN: 0 },
    CONTINGENCY: { MIN: 0 },
  },
  RISKS: {
    DESCRIPTION: { MAX_LENGTH: 500 },
    MITIGATION: { MAX_LENGTH: 500 },
    IMPACT: { VALUES: ['low', 'medium', 'high', 'critical'] as const },
    PROBABILITY: { VALUES: ['low', 'medium', 'high'] as const },
    STATUS: { VALUES: ['identified', 'mitigated', 'occurred'] as const },
  },

  RESOURCES: {
    ESTIMATED_HOURS: { MIN: 0 },
    ACTUAL_HOURS: { MIN: 0 },
    TOOL: { MAX_LENGTH: 100 },
    EXTERNAL_RESOURCE: { MAX_LENGTH: 200 },
  },
  QUALITY_METRICS: {
    REQUIREMENTS_COVERAGE: { MIN: 0, MAX: 100 },
    DEFECT_DENSITY: { MIN: 0 },
    CUSTOMER_SATISFACTION: { MIN: 0, MAX: 5 },
  },
  PAGINATION: { DEFAULT_PAGE: 1, DEFAULT_LIMIT: 10, MAX_LIMIT: 100, MIN_PAGE: 1 },
  SORT: { ALLOWED_FIELDS: ['name', 'status', 'priority', 'createdAt', 'updatedAt', 'startDate', 'endDate'] as const }
} as const

// MongoDB ObjectId validation
export const objectIdSchema = z.string().regex(
  /^[0-9a-fA-F]{24}$/,
  'Invalid ID format'
)

// Base project schema
export const baseProjectSchema = z.object({
  name: z.string()
    .min(PROJECT_CONSTANTS.NAME.MIN_LENGTH, 'Name too short')
    .max(PROJECT_CONSTANTS.NAME.MAX_LENGTH, 'Name too long')
    .transform(val => val.trim())
    .refine(name => name.length > 0, 'Project name is required'),

  description: z.string()
    .max(PROJECT_CONSTANTS.DESCRIPTION.MAX_LENGTH, 'Description too long. Max 1000 words allowed.')
    .nullable()
    .optional()
    .transform(val => !val || val.trim() === '' ? undefined : val.trim()),

  clientId: objectIdSchema,

  departmentIds: z.array(objectIdSchema)
    .optional()
    .default([]),

  status: z.enum(PROJECT_CONSTANTS.STATUS.VALUES)
    .default(PROJECT_CONSTANTS.STATUS.DEFAULT),

  priority: z.enum(PROJECT_CONSTANTS.PRIORITY.VALUES)
    .default(PROJECT_CONSTANTS.PRIORITY.DEFAULT),

  budget: z.number()
    .min(0, 'Budget must be positive')
    .nullable()
    .optional()
    .transform(val => val === null ? undefined : val),

  startDate: z.date()
    .nullable()
    .optional()
    .transform(val => val === null ? undefined : val),

  endDate: z.date()
    .nullable()
    .optional()
    .transform(val => val === null ? undefined : val),

  // Fields from lead project info
  projectType: z.string()
    .max(PROJECT_CONSTANTS.PROJECT_TYPE.MAX_LENGTH, 'Project type too long')
    .nullable()
    .optional()
    .transform(val => !val || val.trim() === '' ? undefined : val.trim()),
  complexity: z.string()
    .max(100, 'Project complexity too long')
    .nullable()
    .optional()
    .transform(val => !val || val.trim() === '' ? undefined : val.trim()),

  requirements: z.array(
    z.string()
      .max(PROJECT_CONSTANTS.REQUIREMENTS.MAX_LENGTH, 'Requirement too long')
      .transform(val => val.trim())
  )
    .optional()
    .default([]),
  customerServices: z.array(
    z.string()
      .max(PROJECT_CONSTANTS.CUSTOMER_SERVICES.MAX_LENGTH, 'Customer service too long')
      .transform(val => val.trim())
  )
    .optional()
    .default([]),

  timeline: z.string()
    .max(PROJECT_CONSTANTS.TIMELINE.MAX_LENGTH, 'Timeline too long')
    .nullable()
    .optional()
    .transform(val => !val || val.trim() === '' ? undefined : val.trim()),

  // Enhanced professional CRM fields
  budgetBreakdown: z.object({
    development: z.number().min(PROJECT_CONSTANTS.BUDGET_BREAKDOWN.DEVELOPMENT.MIN).optional(),
    design: z.number().min(PROJECT_CONSTANTS.BUDGET_BREAKDOWN.DESIGN.MIN).optional(),
    testing: z.number().min(PROJECT_CONSTANTS.BUDGET_BREAKDOWN.TESTING.MIN).optional(),
    deployment: z.number().min(PROJECT_CONSTANTS.BUDGET_BREAKDOWN.DEPLOYMENT.MIN).optional(),
    maintenance: z.number().min(PROJECT_CONSTANTS.BUDGET_BREAKDOWN.MAINTENANCE.MIN).optional(),
    contingency: z.number().min(PROJECT_CONSTANTS.BUDGET_BREAKDOWN.CONTINGENCY.MIN).optional(),
  }).optional(),

  risks: z.array(z.object({
    description: z.string().min(1).max(PROJECT_CONSTANTS.RISKS.DESCRIPTION.MAX_LENGTH).transform(val => val.trim()),
    impact: z.enum(PROJECT_CONSTANTS.RISKS.IMPACT.VALUES).default('medium'),
    probability: z.enum(PROJECT_CONSTANTS.RISKS.PROBABILITY.VALUES).default('medium'),
    mitigation: z.string().max(PROJECT_CONSTANTS.RISKS.MITIGATION.MAX_LENGTH).transform(val => val.trim()).optional(),
    status: z.enum(PROJECT_CONSTANTS.RISKS.STATUS.VALUES).default('identified'),
  })).optional().default([]),

  resources: z.object({
    estimatedHours: z.number().min(PROJECT_CONSTANTS.RESOURCES.ESTIMATED_HOURS.MIN).optional(),
    actualHours: z.number().min(PROJECT_CONSTANTS.RESOURCES.ACTUAL_HOURS.MIN).optional(),
    tools: z.array(z.string().max(PROJECT_CONSTANTS.RESOURCES.TOOL.MAX_LENGTH).transform(val => val.trim())).optional().default([]),
    externalResources: z.array(z.string().max(PROJECT_CONSTANTS.RESOURCES.EXTERNAL_RESOURCE.MAX_LENGTH).transform(val => val.trim())).optional().default([]),
  }).optional(),

  qualityMetrics: z.object({
    requirementsCoverage: z.number().min(PROJECT_CONSTANTS.QUALITY_METRICS.REQUIREMENTS_COVERAGE.MIN).max(PROJECT_CONSTANTS.QUALITY_METRICS.REQUIREMENTS_COVERAGE.MAX).optional(),
    defectDensity: z.number().min(PROJECT_CONSTANTS.QUALITY_METRICS.DEFECT_DENSITY.MIN).optional(),
    customerSatisfaction: z.number().min(PROJECT_CONSTANTS.QUALITY_METRICS.CUSTOMER_SATISFACTION.MIN).max(PROJECT_CONSTANTS.QUALITY_METRICS.CUSTOMER_SATISFACTION.MAX).optional(),
    onTimeDelivery: z.boolean().default(false),
    withinBudget: z.boolean().default(false),
  }).optional(),

  // Approval fields
  approvedBy: objectIdSchema.nullable().optional(),
  approvedAt: z.date().nullable().optional(),

  // Soft delete fields
  isDeleted: z.boolean().default(false).optional(),
  deletedAt: z.date().nullable().optional(),
  deletedBy: objectIdSchema.nullable().optional(),
  deletionReason: z.string().max(500, 'Deletion reason too long').nullable().optional().transform(val => !val || val.trim() === '' ? undefined : val.trim()),

  createdBy: objectIdSchema,
})

// Form schemas (with string dates for form handling)
export const baseProjectFormSchema = z.object({
  name: z.string()
    .min(PROJECT_CONSTANTS.NAME.MIN_LENGTH, 'Name too short')
    .max(PROJECT_CONSTANTS.NAME.MAX_LENGTH, 'Name too long')
    .transform(val => val.trim()),

  description: z.string()
    .max(PROJECT_CONSTANTS.DESCRIPTION.MAX_LENGTH, 'Description too long. Max 1000 words allowed.')
    .optional()
    .transform(val => !val || val.trim() === '' ? undefined : val.trim()),

  clientId: z.string()
    .transform(val => val?.trim() || '')
    .refine(val => val.length > 0, 'Client is required'),

  departmentIds: z.array(z.string())
    .optional()
    .default([]),

  status: z.enum(PROJECT_CONSTANTS.STATUS.VALUES)
    .default(PROJECT_CONSTANTS.STATUS.DEFAULT),

  priority: z.enum(PROJECT_CONSTANTS.PRIORITY.VALUES)
    .default(PROJECT_CONSTANTS.PRIORITY.DEFAULT),

  budget: z.union([z.string(), z.number()])
    .optional()
    .transform(val => {
      if (val === undefined || val === null || val === '') return undefined;
      const num = typeof val === 'string' ? parseFloat(val) : val;
      return isNaN(num) ? undefined : num;
    })
    .refine(val => val === undefined || val >= 0, 'Budget must be positive'),

  startDate: z.string()
    .optional()
    .transform(val => !val || val.trim() === '' ? undefined : val.trim()),

  endDate: z.string()
    .optional()
    .transform(val => !val || val.trim() === '' ? undefined : val.trim()),

  // Fields from lead project info
  projectType: z.string()
    .max(PROJECT_CONSTANTS.PROJECT_TYPE.MAX_LENGTH, 'Project type too long')
    .optional()
    .transform(val => !val || val.trim() === '' ? undefined : val.trim()),
  complexity: z.string()
    .max(100, 'Complexity too long')
    .optional()
    .transform(val => !val || val.trim() === '' ? undefined : val.trim()),

  requirements: z.array(
    z.string()
      .max(PROJECT_CONSTANTS.REQUIREMENTS.MAX_LENGTH, 'Requirement too long')
      .transform(val => val.trim())
  )
    .optional()
    .default([]),
  customerServices: z.array(
    z.string()
      .max(PROJECT_CONSTANTS.CUSTOMER_SERVICES.MAX_LENGTH, 'Customer service too long')
      .transform(val => val.trim())
  )
    .optional()
    .default([]),

  timeline: z.string()
    .max(PROJECT_CONSTANTS.TIMELINE.MAX_LENGTH, 'Timeline too long')
    .optional()
    .transform(val => !val || val.trim() === '' ? undefined : val.trim()),

  // Enhanced
  budgetBreakdown: z.object({
    development: z.union([z.string(), z.number()])
      .optional()
      .transform(val => {
        if (val === undefined || val === null || val === '') return undefined;
        const num = typeof val === 'string' ? parseFloat(val) : val;
        return isNaN(num) ? undefined : num;
      }),
    design: z.union([z.string(), z.number()])
      .optional()
      .transform(val => {
        if (val === undefined || val === null || val === '') return undefined;
        const num = typeof val === 'string' ? parseFloat(val) : val;
        return isNaN(num) ? undefined : num;
      }),
    testing: z.union([z.string(), z.number()])
      .optional()
      .transform(val => {
        if (val === undefined || val === null || val === '') return undefined;
        const num = typeof val === 'string' ? parseFloat(val) : val;
        return isNaN(num) ? undefined : num;
      }),
    deployment: z.union([z.string(), z.number()])
      .optional()
      .transform(val => {
        if (val === undefined || val === null || val === '') return undefined;
        const num = typeof val === 'string' ? parseFloat(val) : val;
        return isNaN(num) ? undefined : num;
      }),
    maintenance: z.union([z.string(), z.number()])
      .optional()
      .transform(val => {
        if (val === undefined || val === null || val === '') return undefined;
        const num = typeof val === 'string' ? parseFloat(val) : val;
        return isNaN(num) ? undefined : num;
      }),
    contingency: z.union([z.string(), z.number()])
      .optional()
      .transform(val => {
        if (val === undefined || val === null || val === '') return undefined;
        const num = typeof val === 'string' ? parseFloat(val) : val;
        return isNaN(num) ? undefined : num;
      }),
  }).optional(),


  risks: z.array(z.object({
    description: z.string().min(1).max(PROJECT_CONSTANTS.RISKS.DESCRIPTION.MAX_LENGTH),
    impact: z.enum(PROJECT_CONSTANTS.RISKS.IMPACT.VALUES).default('medium'),
    probability: z.enum(PROJECT_CONSTANTS.RISKS.PROBABILITY.VALUES).default('medium'),
    mitigation: z.string().max(PROJECT_CONSTANTS.RISKS.MITIGATION.MAX_LENGTH).optional(),
    status: z.enum(PROJECT_CONSTANTS.RISKS.STATUS.VALUES).default('identified'),
  })).optional().default([]),


  resources: z.object({
    estimatedHours: z.union([z.string(), z.number()])
      .optional()
      .transform(val => {
        if (val === undefined || val === null || val === '') return undefined;
        const num = typeof val === 'string' ? parseFloat(val) : val;
        return isNaN(num) ? undefined : num;
      }),
    actualHours: z.union([z.string(), z.number()])
      .optional()
      .transform(val => {
        if (val === undefined || val === null || val === '') return undefined;
        const num = typeof val === 'string' ? parseFloat(val) : val;
        return isNaN(num) ? undefined : num;
      }),
    tools: z.array(z.string().max(PROJECT_CONSTANTS.RESOURCES.TOOL.MAX_LENGTH)).optional().default([]),
    externalResources: z.array(z.string().max(PROJECT_CONSTANTS.RESOURCES.EXTERNAL_RESOURCE.MAX_LENGTH)).optional().default([]),
  }).optional(),
})

// Operation-specific schemas
export const createProjectSchema = baseProjectSchema
  .omit({ createdBy: true })
  .strict()
  .refine(data => {
    if (data.startDate && data.endDate && data.startDate > data.endDate) {
      return false
    }
    return true
  }, { message: 'Start date cannot be after end date' })

export const updateProjectSchema = baseProjectSchema
  .omit({ createdBy: true })
  .partial()
  .extend({
    // Allow isDeleted field only when restoring (setting to false)
    isDeleted: z.literal(false).optional(),
  })
  .strict()
  .refine(data => Object.values(data).some(value =>
    value !== undefined && value !== null && value !== ''
  ), { message: 'At least one field must be provided for update' })
  .refine(data => {
    if (data.startDate && data.endDate && data.startDate > data.endDate) {
      return false
    }
    return true
  }, { message: 'Start date cannot be after end date' })

// Form operation schemas
export const createProjectFormSchema = baseProjectFormSchema.strict()

export const updateProjectFormSchema = baseProjectFormSchema
  .extend({
    id: z.string().optional(),
    // Allow isDeleted field only when restoring (setting to false)
    isDeleted: z.literal(false).optional(),
  })
  .partial()
  .strict()
  .refine(data => {
    // Simplified check - if any top-level field has a truthy value
    const hasUpdate = Object.entries(data).some(([key, value]) => {
      // Skip completely empty values
      if (value === undefined || value === null || value === '') return false;

      // For objects, check if they have any meaningful content
      if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        return Object.values(value).some(v => {
          if (typeof v === 'string') {
            return v !== '';
          }
          if (Array.isArray(v)) {
            return v.length > 0;
          }
          return v !== undefined && v !== null;
        });
      }

      // For arrays, allow empty arrays as valid updates (user might want to clear all items)
      if (Array.isArray(value)) {
        return true; // Empty arrays are valid updates
      }

      return true;
    });

    console.log('🔍 Validation refine check:', { hasUpdate, data: Object.keys(data) });
    return hasUpdate;
  }, {
    message: 'At least one field must be provided for update',
    path: ['_form']
  })

// Department categorization schema
export const categorizeDepartmentsSchema = z.object({
  departmentIds: z.array(objectIdSchema)
    .min(1, 'At least one department must be selected')
    .max(10, 'Maximum 10 departments allowed'),
})

// ID parameter schema
export const projectIdSchema = z.object({
  id: objectIdSchema
})

// Query parameter schemas
export const projectQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(10),
  search: z.string().optional().transform(val => val?.trim() || ''),
  status: z.enum(['pending', 'active', 'completed', 'approved', 'inactive', 'deleted', '']).optional(),
  priority: z.enum(['low', 'medium', 'high', 'urgent', '']).optional(),
  clientId: objectIdSchema.optional(),
  departmentId: objectIdSchema.optional(),
  sortBy: z.enum(['name', 'status', 'priority', 'createdAt', 'updatedAt', 'startDate', 'endDate']).default('createdAt'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
})

// Project prefill schema (from lead data)
export const projectPrefillSchema = z.object({
  clientId: objectIdSchema,
  leadId: objectIdSchema.optional(),
  // Auto-filled from lead project info
  name: z.string().optional(),
  projectType: z.string().optional(),
  complexity: z.string().optional(),
  requirements: z.array(z.string()).optional(),
  customerServices: z.array(z.string()).optional(),
  timeline: z.string().optional(),
  budget: z.number().optional(),
})

// Project stats schema
export const projectStatsSchema = z.object({
  totalProjects: z.number(),
  pendingProjects: z.number(),
  activeProjects: z.number(),
  completedProjects: z.number(),
  approvedProjects: z.number(),
  inactiveProjects: z.number(),

  // Priority breakdown
  lowPriorityProjects: z.number(),
  mediumPriorityProjects: z.number(),
  highPriorityProjects: z.number(),
  urgentPriorityProjects: z.number(),

  // Budget stats
  totalBudget: z.number().optional(),
  averageBudget: z.number().optional(),
})

// Type exports for frontend
export type Project = {
  _id: string
  name: string
  description?: string
  clientId: string
  departmentIds: string[]
  status: 'pending' | 'active' | 'completed' | 'approved' | 'inactive' | 'deleted'
  priority: 'low' | 'medium' | 'high' | 'urgent'
  budget?: number
  startDate?: string
  endDate?: string
  complexity?: string
  projectType?: string
  requirements?: string[]
  customerServices?: string[]
  timeline?: string
  createdBy: string
  approvedBy?: string
  approvedAt?: string
  createdAt: string
  updatedAt: string

  // Virtual fields
  client?: {
    _id: string
    name: string
    email: string
  }
  departments?: Array<{
    _id: string
    name: string
    status: string
  }>
  creator?: {
    _id: string
    name: string
    email: string
  }
  taskCount?: number
}

export type CreateProjectData = z.infer<typeof createProjectSchema>
export type UpdateProjectData = z.infer<typeof updateProjectSchema>
export type CreateProjectFormData = z.infer<typeof createProjectFormSchema>
export type UpdateProjectFormData = z.infer<typeof updateProjectFormSchema>
export type ProjectQueryParams = z.infer<typeof projectQuerySchema>
export type ProjectPrefillData = z.infer<typeof projectPrefillSchema>
export type ProjectStats = z.infer<typeof projectStatsSchema>
export type CategorizeDepartmentsData = z.infer<typeof categorizeDepartmentsSchema>

// Fetch params interface
export interface FetchProjectsParams extends Partial<ProjectQueryParams> { }

// Project filter interface
export interface ProjectFilters {
  search?: string
  status?: 'pending' | 'active' | 'completed' | 'approved' | 'inactive' | 'deleted' | ''
  priority?: 'low' | 'medium' | 'high' | 'urgent' | ''
  clientId?: string
  departmentId?: string
}

// Project sort interface
export interface ProjectSort {
  field: 'name' | 'status' | 'priority' | 'createdAt' | 'updatedAt' | 'startDate' | 'endDate'
  direction: 'asc' | 'desc'
}