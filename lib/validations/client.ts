import { z } from "zod"
import {
  objectIdSchema,
  nameSchema,
  emailSchema,
  phoneSchema,
  addressSchema,
  socialLinksSchema,
  metadataSchema
} from "./user"

// =============================================================================
// CLIENT-SPECIFIC CONSTANTS
// =============================================================================

export const CLIENT_CONSTANTS = {
  NAME: { MIN_LENGTH: 2, MAX_LENGTH: 100 },
  EMAIL: { MAX_LENGTH: 254 },
  PHONE: { PATTERN: /^[\+]?[0-9]{7,15}$/ },
  STATUS: {
    VALUES: ['active', 'inactive', 'deleted', 'qualified', 'unqualified'] as const,
    DEFAULT: 'qualified' as const,
    CLIENT_VALUES: ['qualified', 'unqualified'] as const, // Client-specific statuses
  },
  COMPANY: { MIN_LENGTH: 2, MAX_LENGTH: 200 },
  PROJECT_INTERESTS: { MAX_COUNT: 10, MAX_LENGTH: 100 },
  PAGINATION: { DEFAULT_PAGE: 1, DEFAULT_LIMIT: 10, MAX_LIMIT: 100, MIN_PAGE: 1 },
  SORT: { ALLOWED_FIELDS: ['name', 'email', 'company', 'clientStatus', 'status', 'createdAt', 'updatedAt'] as const }
} as const

// =============================================================================
// CLIENT-SPECIFIC VALIDATION SCHEMAS
// =============================================================================

// Client status validation
const clientStatusSchema = z.enum(CLIENT_CONSTANTS.STATUS.CLIENT_VALUES)

// Company validation (required for clients)
const clientCompanySchema = z
  .string()
  .min(CLIENT_CONSTANTS.COMPANY.MIN_LENGTH, `Company name must be at least ${CLIENT_CONSTANTS.COMPANY.MIN_LENGTH} characters`)
  .max(CLIENT_CONSTANTS.COMPANY.MAX_LENGTH, `Company name must not exceed ${CLIENT_CONSTANTS.COMPANY.MAX_LENGTH} characters`)
  .transform((company) => company.trim())


// Lead ID validation
const leadIdSchema = objectIdSchema.optional()

// =============================================================================
// CORE CLIENT SCHEMAS
// =============================================================================

// Base client object schema (without refinements for composability)
export const baseClientObjectSchema = z.object({
  // Basic user fields
  name: nameSchema,
  email: emailSchema,
  phone: phoneSchema,

  // User role and department fields
  role: objectIdSchema,
  department: objectIdSchema,
  position: z.string().trim().optional(),

  // User status (extended for clients)
  status: z.enum(CLIENT_CONSTANTS.STATUS.VALUES).default(CLIENT_CONSTANTS.STATUS.DEFAULT),

  // Client-specific fields
  isClient: z.literal(true), // Always true for clients
  leadId: leadIdSchema,
  clientStatus: clientStatusSchema,
  company: clientCompanySchema,
  industry: z.string().optional(),
  website: z.string().optional(),
  companySize: z.enum(['startup', 'small', 'medium', 'large', 'enterprise']).optional(),
  annualRevenue: z.string().optional(), // Keep as string for form
  employeeCount: z.string().optional(), // Keep as string for form

  // Optional user fields
  avatar: z.string().url().optional().or(z.literal("")),
  address: addressSchema,
  socialLinks: socialLinksSchema,
  metadata: metadataSchema,

  // Security fields
  emailVerified: z.boolean().default(false),
  phoneVerified: z.boolean().default(false),
  twoFactorEnabled: z.boolean().default(false),

  // Additional permissions
  permissions: z.array(z.string()).default([]),

  // Notes
  notes: z.string().max(2000).optional(),
})

// Base client schema with refinements
export const baseClientSchema = baseClientObjectSchema.refine((data: any) => {
  // Client status and general status should align
  if (data.clientStatus === 'qualified' && !['active', 'qualified'].includes(data.status)) {
    return false
  }
  if (data.clientStatus === 'unqualified' && data.status !== 'unqualified') {
    return false
  }
  return true
}, {
  message: 'Client status must align with general status',
  path: ['status']
})

// =============================================================================
// OPERATION SPECIFIC SCHEMAS
// =============================================================================

// Create client schema (used when creating from lead qualification)
export const createClientSchema = baseClientObjectSchema.omit({
  isClient: true, // Always set to true
}).extend({
  // Make password optional for clients (they can set it later)
  password: z.string()
    .min(8, "Password must be at least 8 characters")
    .max(128, "Password must not exceed 128 characters")
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
      "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character"
    )
    .optional(),

  // Role will be set automatically to 'client' role
  role: objectIdSchema.optional(),

  // Department can be inherited from lead creator or set to a default client department
  department: objectIdSchema.optional(),
  departmentId: objectIdSchema.optional(), // Alias for department
}).strict()

// Update client schema
export const updateClientSchema = baseClientObjectSchema.omit({
  isClient: true, // Cannot change client flag
}).partial().extend({
  // Allow password updates (optional)
  password: z.string()
    .min(8, "Password must be at least 8 characters")
    .max(128, "Password must not exceed 128 characters")
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
      "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character"
    )
    .optional(),
  // Allow isDeleted field only when restoring (setting to false)
  isDeleted: z.literal(false).optional(),
}).strict().refine((data: any) => {
  // At least one field must be provided for update
  const values = Object.values(data).filter(value =>
    value !== undefined && value !== null && value !== ''
  )
  return values.length > 0
}, { message: 'At least one field must be provided for update' })

// Client status update schema
export const clientStatusUpdateSchema = z.object({
  clientStatus: clientStatusSchema,
  status: z.enum(CLIENT_CONSTANTS.STATUS.VALUES),
  reason: z.string()
    .max(500, "Reason must not exceed 500 characters")
    .optional(),
}).refine(data => {
  // Reason required when changing to unqualified
  if (data.clientStatus === 'unqualified' && !data.reason) {
    return false
  }

  // Status alignment validation
  if (data.clientStatus === 'qualified' && !['active', 'qualified'].includes(data.status)) {
    return false
  }
  if (data.clientStatus === 'unqualified' && data.status !== 'unqualified') {
    return false
  }

  return true
}, {
  message: 'Invalid status combination or missing unqualification reason',
})

// Client from lead creation schema
export const createClientFromLeadSchema = z.object({
  leadId: objectIdSchema,
  createdBy: objectIdSchema.optional(), // Will be set from authenticated user if not provided
  // Additional client-specific data can be provided
  password: z.string()
    .min(8, "Password must be at least 8 characters")
    .max(128, "Password must not exceed 128 characters")
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
      "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character"
    )
    .optional(),
  notes: z.string().max(2000, "Notes must not exceed 2000 characters").optional(),
}).strict()

// =============================================================================
// QUERY PARAMETER SCHEMAS
// =============================================================================

// Client query parameters (independent schema for clients)
export const clientQuerySchema = z.object({
  page: z.coerce.number().int().min(CLIENT_CONSTANTS.PAGINATION.MIN_PAGE).default(CLIENT_CONSTANTS.PAGINATION.DEFAULT_PAGE),
  limit: z.coerce.number().int().min(1).max(CLIENT_CONSTANTS.PAGINATION.MAX_LIMIT).default(CLIENT_CONSTANTS.PAGINATION.DEFAULT_LIMIT),
  search: z.string().optional().transform(val => val?.trim() || ''),

  // Client-specific filters
  clientStatus: z.enum(['qualified', 'unqualified', '']).optional(),
  status: z.enum(['active', 'inactive', 'qualified', 'unqualified', 'deleted', '']).optional(),
  hasLead: z.coerce.boolean().optional(), // Filter clients with/without lead association
  company: z.string().optional().transform(val => val?.trim() || ''),
  website: z.string().optional().transform(val => val?.trim() || ''),

  // Sort options
  sortBy: z.enum(CLIENT_CONSTANTS.SORT.ALLOWED_FIELDS).default('createdAt'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),

  // Date filters for client creation
  qualifiedAfter: z.coerce.date().optional(),
  qualifiedBefore: z.coerce.date().optional(),
}).transform((data: any) => {
  // Always filter for clients only
  return {
    ...data,
    isClient: true, // Always filter for clients
  }
})

// Client ID parameter validation
export const clientIdSchema = z.object({
  id: objectIdSchema
})

// Bulk client operations
export const bulkClientOperationSchema = z.object({
  clientIds: z.array(objectIdSchema).min(1, 'At least one client ID is required').max(50, 'Cannot process more than 50 clients at once'),
  operation: z.enum(['updateStatus', 'assignProject', 'bulkNote']),
  data: z.object({
    clientStatus: clientStatusSchema.optional(),
    status: z.enum(CLIENT_CONSTANTS.STATUS.VALUES).optional(),
    projectId: objectIdSchema.optional(),
    notes: z.string().max(2000, "Notes must not exceed 2000 characters").optional(),
  }).optional(),
})

// =============================================================================
// TYPE EXPORTS
// =============================================================================

// Client with ID (for responses)
export const clientWithIdSchema = baseClientObjectSchema.extend({
  _id: objectIdSchema,
  createdAt: z.date(),
  updatedAt: z.date(),
  lastLogin: z.date().optional(),
})

// TypeScript type definitions
export type Client = z.infer<typeof clientWithIdSchema>
export type CreateClientData = z.infer<typeof createClientSchema>
export type UpdateClientData = z.infer<typeof updateClientSchema>
export type ClientStatusUpdate = z.infer<typeof clientStatusUpdateSchema>
export type CreateClientFromLead = z.infer<typeof createClientFromLeadSchema>
export type ClientQueryParams = z.infer<typeof clientQuerySchema>
export type ClientIdParams = z.infer<typeof clientIdSchema>
export type BulkClientOperation = z.infer<typeof bulkClientOperationSchema>

// Additional helper types
export type ClientStatus = (typeof CLIENT_CONSTANTS.STATUS.CLIENT_VALUES)[number]
export type ClientSortField = (typeof CLIENT_CONSTANTS.SORT.ALLOWED_FIELDS)[number]

// Client filters type for frontend
export type ClientFilters = Partial<{
  search: string
  status: string
  clientStatus: ClientStatus | ''
  company: string
  website: string
  department: string
  hasLead: boolean
  qualifiedAfter: Date
  qualifiedBefore: Date
}>

// Client sort configuration
export type ClientSort = {
  field: ClientSortField
  direction: 'asc' | 'desc'
}

// Client pagination configuration  
export type ClientPagination = {
  page: number
  limit: number
  total: number
  pages: number
}

// Client stats type
export type ClientStats = {
  totalClients: number
  qualifiedClients: number
  unqualifiedClients: number
  activeClients: number
  newClientsThisMonth: number
  clientsWithProjects: number
}

// Client API response types
export type ClientListResponse = {
  success: boolean
  data: {
    clients: Client[]
    pagination: ClientPagination
    stats: ClientStats
  }
  message: string
}

export type ClientResponse = {
  success: boolean
  data: Client
  message: string
}

export type ClientMutationResponse = {
  success: boolean
  data: Client
  message: string
}

export const createClientFormSchema = z.object({
  // Basic Information
  name: z.string().min(CLIENT_CONSTANTS.NAME.MIN_LENGTH).max(CLIENT_CONSTANTS.NAME.MAX_LENGTH),
  email: z.string().email().max(CLIENT_CONSTANTS.EMAIL.MAX_LENGTH),
  phone: z.string().optional(),
  position: z.string().optional(),

  // Company Information
  company: z.string().min(CLIENT_CONSTANTS.COMPANY.MIN_LENGTH).max(CLIENT_CONSTANTS.COMPANY.MAX_LENGTH),
  website: z.string().min(CLIENT_CONSTANTS.COMPANY.MIN_LENGTH).max(CLIENT_CONSTANTS.COMPANY.MAX_LENGTH),
  industry: z.string().optional(),
  companySize: z.enum(['', 'startup', 'small', 'medium', 'large', 'enterprise']).optional(),
  annualRevenue: z.string().optional(), // Keep as string for form
  employeeCount: z.string().optional(), // Keep as string for form

  // Client Status
  clientStatus: z.enum(CLIENT_CONSTANTS.STATUS.CLIENT_VALUES).default(CLIENT_CONSTANTS.STATUS.DEFAULT),
  status: z.enum(CLIENT_CONSTANTS.STATUS.VALUES).default(CLIENT_CONSTANTS.STATUS.DEFAULT),

  // Address Information
  address: z.object({
    street: z.string().optional(),
    city: z.string().optional(),
    state: z.string().optional(),
    zipCode: z.string().optional(),
    country: z.string().optional(),
  }).optional(),

  // Social Links
  socialLinks: z.array(z.object({
    linkName: z.string().min(1, "Platform name is required"),
    linkUrl: z.string().url("Must be a valid URL"),
  })).optional(),


  // Notes
  notes: z.string().max(2000).optional(),
}).strict()

// Update form schema (string inputs for form handling)
export const updateClientFormSchema = z.object({
  // Basic Information
  name: z.string().min(CLIENT_CONSTANTS.NAME.MIN_LENGTH).max(CLIENT_CONSTANTS.NAME.MAX_LENGTH),
  email: emailSchema,
  phone: z.string().optional(),
  position: z.string().optional(),

  // Company Information
  company: z.string().min(CLIENT_CONSTANTS.COMPANY.MIN_LENGTH).max(CLIENT_CONSTANTS.COMPANY.MAX_LENGTH),
  website: z.string().min(CLIENT_CONSTANTS.COMPANY.MIN_LENGTH).max(CLIENT_CONSTANTS.COMPANY.MAX_LENGTH),
  industry: z.string().optional(),
  companySize: z.enum(['', 'startup', 'small', 'medium', 'large', 'enterprise']).optional(),
  annualRevenue: z.string().optional(), // Keep as string for form
  employeeCount: z.string().optional(), // Keep as string for form

  // Client Status
  clientStatus: z.enum(CLIENT_CONSTANTS.STATUS.CLIENT_VALUES).default(CLIENT_CONSTANTS.STATUS.DEFAULT),
  status: z.enum(CLIENT_CONSTANTS.STATUS.VALUES).default(CLIENT_CONSTANTS.STATUS.DEFAULT),


  // Address Information
  address: z.object({
    street: z.string().optional(),
    city: z.string().optional(),
    state: z.string().optional(),
    zipCode: z.string().optional(),
    country: z.string().optional(),
  }).optional(),

  // Social Links
  socialLinks: z.array(z.object({
    linkName: z.string().min(1, "Platform name is required"),
    linkUrl: z.string().url("Must be a valid URL"),
  })).optional(),
  
  // Notes
  notes: z.string().max(2000).optional(),
}).strict()

// Export types
export type CreateClientFormData = z.infer<typeof createClientFormSchema>
export type UpdateClientFormData = z.infer<typeof updateClientFormSchema>

// Lead synchronization types
export type LeadClientSync = {
  leadId: string
  clientId: string
  syncType: 'qualification' | 'unqualification' | 'status_update'
  reason?: string
  syncedAt: Date
  syncedBy: string
}