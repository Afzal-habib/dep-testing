import { z } from 'zod'

// Constants for validation
export const TASK_CONSTANTS = {
  TITLE: { MIN_LENGTH: 2, MAX_LENGTH: 300 },
  DESCRIPTION: { MAX_LENGTH: 2000 },
  STATUS: { 
    VALUES: ['pending', 'in-progress', 'completed', 'on-hold', 'cancelled', 'closed', 'deleted'] as const, 
    DEFAULT: 'pending' as const 
  },
  PRIORITY: { 
    VALUES: ['low', 'medium', 'high', 'urgent'] as const, 
    DEFAULT: 'medium' as const 
  },
  TYPE: { 
    VALUES: ['task', 'sub-task'] as const, 
    DEFAULT: 'task' as const 
  },
  PAGINATION: { DEFAULT_PAGE: 1, DEFAULT_LIMIT: 10, MAX_LIMIT: 100, MIN_PAGE: 1 },
  SORT: { ALLOWED_FIELDS: ['title', 'status', 'priority', 'type', 'createdAt', 'updatedAt', 'dueDate'] as const }
} as const

// MongoDB ObjectId validation
export const objectIdSchema = z.string().regex(
  /^[0-9a-fA-F]{24}$/,
  'Invalid ID format'
)

// Optional ObjectId schema that allows undefined/empty values
export const optionalObjectIdSchema = z.string()
  .optional()
  .refine(val => !val || val === '' || /^[0-9a-fA-F]{24}$/.test(val), {
    message: 'Invalid ID format'
  })
  .transform(val => !val || val.trim() === '' ? undefined : val.trim())

// Query ObjectId schema that allows empty strings
export const queryObjectIdSchema = z.string()
  .optional()
  .refine(val => !val || val === '' || /^[0-9a-fA-F]{24}$/.test(val), {
    message: 'Invalid ID format'
  })
  .transform(val => !val || val.trim() === '' ? undefined : val.trim())

// Base task schema
export const baseTaskSchema = z.object({
  title: z.string()
    .min(TASK_CONSTANTS.TITLE.MIN_LENGTH, 'Title too short minimum 2 characters required')
    .max(TASK_CONSTANTS.TITLE.MAX_LENGTH, 'Title too long only 300 characters allowed')
    .transform(val => val.trim())
    .refine(title => title.length > 0, 'Task title is required'),

  description: z.string()
    .max(TASK_CONSTANTS.DESCRIPTION.MAX_LENGTH, 'Description too long')
    .nullable()
    .optional()
    .transform(val => !val || val.trim() === '' ? undefined : val.trim()),

  projectId: objectIdSchema,
  
  departmentId: objectIdSchema,

  parentTaskId: optionalObjectIdSchema,

  assigneeId: optionalObjectIdSchema,

  status: z.enum(TASK_CONSTANTS.STATUS.VALUES)
    .default(TASK_CONSTANTS.STATUS.DEFAULT),

  priority: z.enum(TASK_CONSTANTS.PRIORITY.VALUES)
    .default(TASK_CONSTANTS.PRIORITY.DEFAULT),

  type: z.enum(TASK_CONSTANTS.TYPE.VALUES)
    .default(TASK_CONSTANTS.TYPE.DEFAULT),

  labelIds: z.array(objectIdSchema)
    .optional()
    .default([]),

  estimatedHours: z.number()
    .min(0, 'Estimated hours must be positive')
    .nullable()
    .optional()
    .transform(val => val === null ? undefined : val),

  actualHours: z.number()
    .min(0, 'Actual hours must be positive')
    .nullable()
    .optional()
    .transform(val => val === null ? undefined : val),

  startDate: z.date()
    .nullable()
    .optional()
    .transform(val => val === null ? undefined : val),

  dueDate: z.date()
    .nullable()
    .optional()
    .transform(val => val === null ? undefined : val),

  completedAt: z.date()
    .nullable()
    .optional()
    .transform(val => val === null ? undefined : val),

  // Soft delete fields
  isDeleted: z.boolean().default(false).optional(),
  deletedAt: z.date().nullable().optional(),
  deletedBy: objectIdSchema.nullable().optional(),
  deletionReason: z.string().max(500, 'Deletion reason too long').nullable().optional().transform(val => !val || val.trim() === '' ? undefined : val.trim()),

  createdBy: objectIdSchema,
  
  assignedBy: objectIdSchema
    .nullable()
    .optional()
    .transform(val => val === null || val === '' ? undefined : val),
})

// Form schemas (with string inputs for form handling)
export const baseTaskFormSchema = z.object({
  title: z.string()
    .min(TASK_CONSTANTS.TITLE.MIN_LENGTH, 'Title too short minimum 2 characters required')
    .max(TASK_CONSTANTS.TITLE.MAX_LENGTH, 'Title too long only 300 characters allowed')
    .transform(val => val.trim()),

  description: z.string()
    .max(TASK_CONSTANTS.DESCRIPTION.MAX_LENGTH, 'Description too long')
    .optional()
    .transform(val => !val || val.trim() === '' ? undefined : val.trim()),

  projectId: z.string()
    .min(1, 'Project is required')
    .refine(val => /^[0-9a-fA-F]{24}$/.test(val), {
      message: 'Invalid project ID format'
    })
    .transform(val => val.trim()),
  
  departmentId: z.string()
    .min(1, 'Department is required')
    .refine(val => /^[0-9a-fA-F]{24}$/.test(val), {
      message: 'Invalid department ID format'
    })
    .transform(val => val.trim()),

  parentTaskId: z.string()
    .optional()
    .nullable()
    .refine(val => !val || val === '' || /^[0-9a-fA-F]{24}$/.test(val), {
      message: 'Invalid parent task ID format'
    })
    .transform(val => !val || val.trim() === '' ? undefined : val.trim()),

  assigneeId: z.string()
    .optional()
    .nullable()
    .refine(val => !val || val === '' || /^[0-9a-fA-F]{24}$/.test(val), {
      message: 'Invalid assignee ID format'
    })
    .transform(val => !val || val.trim() === '' ? undefined : val.trim()),


  status: z.enum(TASK_CONSTANTS.STATUS.VALUES)
    .default(TASK_CONSTANTS.STATUS.DEFAULT),

  priority: z.enum(TASK_CONSTANTS.PRIORITY.VALUES)
    .default(TASK_CONSTANTS.PRIORITY.DEFAULT),

  type: z.enum(TASK_CONSTANTS.TYPE.VALUES)
    .default(TASK_CONSTANTS.TYPE.DEFAULT),

  labelIds: z.array(z.string())
    .optional()
    .default([])
    .transform(arr => arr.filter(id => id && /^[0-9a-fA-F]{24}$/.test(id))),

  estimatedHours: z.string()
    .optional()
    .transform(val => !val || val.trim() === '' ? undefined : val.trim()),

  actualHours: z.string()
    .optional()
    .transform(val => !val || val.trim() === '' ? undefined : val.trim()),

  startDate: z.string()
    .optional()
    .transform(val => !val || val.trim() === '' ? undefined : val.trim()),

  dueDate: z.string()
    .optional()
    .transform(val => !val || val.trim() === '' ? undefined : val.trim()),

  completedAt: z.string()
    .optional()
    .transform(val => !val || val.trim() === '' ? undefined : val.trim()),
})

// Operation-specific schemas
export const createTaskSchema = baseTaskSchema
  .omit({ createdBy: true, assignedBy: true })
  .strict()
  .refine(data => {
    // Sub-tasks must have a parent task
    if (data.type === 'sub-task' && !data.parentTaskId) {
      return false
    }
    // Tasks cannot have a parent
    if (data.type === 'task' && data.parentTaskId) {
      return false
    }
    return true
  }, { 
    message: 'Sub-tasks must have a parent task, tasks cannot have a parent' 
  })
  .refine(data => {
    if (data.startDate && data.dueDate && data.startDate > data.dueDate) {
      return false
    }
    return true
  }, { message: 'Start date cannot be after due date' })

export const updateTaskSchema = baseTaskSchema
  .omit({ createdBy: true })
  .partial()
  .extend({
    // Allow isDeleted field only when restoring (setting to false)
    isDeleted: z.literal(false).optional(),
    completedAt: z.string()
      .optional()
      .transform(val => !val || val === '' ? undefined : val),
  })
  .strict()
  .refine(data => Object.values(data).some(value => 
    value !== undefined && value !== null && value !== ''
  ), { message: 'At least one field must be provided for update' })
  .refine(data => {
    if (data.startDate && data.dueDate && data.startDate > data.dueDate) {
      return false
    }
    return true
  }, { message: 'Start date cannot be after due date' })

// Form operation schemas
export const createTaskFormSchema = baseTaskFormSchema
  .strict()
  .refine(data => {
    // Sub-tasks must have a parent task
    if (data.type === 'sub-task' && !data.parentTaskId) {
      return false
    }
    // Tasks cannot have a parent
    if (data.type === 'task' && data.parentTaskId) {
      return false
    }
    return true
  }, { 
    message: 'Sub-tasks must have a parent task, tasks cannot have a parent' 
  })

export const updateTaskFormSchema = baseTaskFormSchema
  .extend({
    // Allow isDeleted field only when restoring (setting to false)
    isDeleted: z.literal(false).optional(),
  })
  .partial()
  .strict()
  .refine(data => Object.values(data).some(value => 
    value !== undefined && value !== null && value !== ''
  ), { message: 'At least one field must be provided for update' })

// Assignment schema
export const assignTaskSchema = z.object({
  assigneeId: objectIdSchema,
  assignedBy: objectIdSchema,
})

// Status update schema
export const updateTaskStatusSchema = z.object({
  status: z.enum(TASK_CONSTANTS.STATUS.VALUES),
  actualHours: z.number().min(0).optional(),
})

// Bulk operations schema
export const bulkUpdateTasksSchema = z.object({
  taskIds: z.array(objectIdSchema).min(1, 'At least one task must be selected'),
  updates: z.object({
    status: z.enum(TASK_CONSTANTS.STATUS.VALUES).optional(),
    priority: z.enum(TASK_CONSTANTS.PRIORITY.VALUES).optional(),
    assigneeId: objectIdSchema.optional(),
  }),
})

// ID parameter schema
export const taskIdSchema = z.object({
  id: objectIdSchema
})

// Query parameter schemas
export const taskQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(10),
  search: z.string().optional().transform(val => val?.trim() || ''),
  status: z.enum(['pending', 'in-progress', 'completed', 'on-hold', 'cancelled', 'closed', 'deleted', '']).optional(),
  priority: z.enum(['low', 'medium', 'high', 'urgent', '']).optional(),
  type: z.enum(['task', 'sub-task', '']).optional(),
  projectId: queryObjectIdSchema,
  departmentId: queryObjectIdSchema,
  assigneeId: queryObjectIdSchema,
  parentTaskId: queryObjectIdSchema,
  dueDateFrom: z.string().optional(),
  dueDateTo: z.string().optional(),
  sortBy: z.enum(['title', 'status', 'priority', 'type', 'createdAt', 'updatedAt', 'dueDate']).default('createdAt'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
})

// Task hierarchy query schema
export const taskHierarchyQuerySchema = z.object({
  projectId: objectIdSchema,
  departmentId: objectIdSchema.optional(),
})

// Task stats schema
export const taskStatsSchema = z.object({
  totalTasks: z.number(),
  pendingTasks: z.number(),
  inProgressTasks: z.number(),
  completedTasks: z.number(),
  onHoldTasks: z.number(),
  cancelledTasks: z.number(),
  
  // Type breakdown
  mainTasks: z.number(),
  subTasks: z.number(),
  
  // Priority breakdown
  lowPriorityTasks: z.number(),
  mediumPriorityTasks: z.number(),
  highPriorityTasks: z.number(),
  urgentPriorityTasks: z.number(),
  
  // Time tracking
  totalEstimatedHours: z.number().optional(),
  totalActualHours: z.number().optional(),
  averageCompletionTime: z.number().optional(),
})

// Type exports for frontend
export type Task = {
  _id: string
  title: string
  description?: string
  projectId: string
  departmentId: string
  parentTaskId?: string
  assigneeId?: string
  
  
  status: 'pending' | 'in-progress' | 'completed' | 'on-hold' | 'cancelled' | 'closed' | 'deleted'
  priority: 'low' | 'medium' | 'high' | 'urgent'
  type: 'task' | 'sub-task'
  estimatedHours?: number
  actualHours?: number
  startDate?: string
  dueDate?: string
  completedAt?: string
  createdBy: string
  assignedBy?: string
  createdAt: string
  updatedAt: string
  
  // Virtual fields
  project?: {
    _id: string
    name: string
    clientId: string
  }
  department?: {
    _id: string
    name: string
  }
  assignee?: {
    _id: string
    name: string
    email: string
  }
  creator?: {
    _id: string
    name: string
    email: string
  }
  assigner?: {
    _id: string
    name: string
    email: string
  }
  parentTask?: {
    _id: string
    title: string
  }
  subTasks?: Task[]
  subTaskCount?: number
}

export type CreateTaskData = z.infer<typeof createTaskSchema>
export type UpdateTaskData = z.infer<typeof updateTaskSchema>
export type CreateTaskFormData = z.infer<typeof createTaskFormSchema>
export type UpdateTaskFormData = z.infer<typeof updateTaskFormSchema>
export type TaskQueryParams = z.infer<typeof taskQuerySchema>
export type TaskHierarchyQueryParams = z.infer<typeof taskHierarchyQuerySchema>
export type TaskStats = z.infer<typeof taskStatsSchema>
export type AssignTaskData = z.infer<typeof assignTaskSchema>
export type UpdateTaskStatusData = z.infer<typeof updateTaskStatusSchema>
export type BulkUpdateTasksData = z.infer<typeof bulkUpdateTasksSchema>

// Fetch params interface
export interface FetchTasksParams extends Partial<TaskQueryParams> {}

// Task filter interface
export interface TaskFilters {
  search?: string
  status?: 'pending' | 'in-progress' | 'completed' | 'on-hold' | 'deleted' | 'closed' | 'cancelled' | ''
  priority?: 'low' | 'medium' | 'high' | 'urgent' | ''
  type?: 'task' | 'sub-task' | ''
  projectId?: string
  departmentId?: string
  assigneeId?: string
  parentTaskId?: string
  dueDateFrom?: string
  dueDateTo?: string
}

// Task sort interface
export interface TaskSort {
  field: 'title' | 'status' | 'priority' | 'type' | 'createdAt' | 'updatedAt' | 'dueDate'
  direction: 'asc' | 'desc'
}

// Task hierarchy interface
export interface TaskHierarchy {
  _id: string
  title: string
  description?: string
  status: 'pending' | 'in-progress' | 'completed' | 'on-hold' | 'deleted' | 'closed' | 'cancelled'
  priority: 'low' | 'medium' | 'high' | 'urgent'
  departmentId: string
  assigneeId?: string
  estimatedHours?: number
  actualHours?: number
  dueDate?: string
  createdAt: string
  
  // Populated fields
  assignee?: {
    _id: string
    name: string
    email: string
  }
  department?: {
    _id: string
    name: string
  }
  
  // Sub-tasks
  subTasks: Array<{
    _id: string
    title: string
    status: 'pending' | 'in-progress' | 'completed' | 'on-hold' | 'closed' | 'deleted' | 'cancelled'
    priority: 'low' | 'medium' | 'high' | 'urgent'
    assigneeId?: string
    dueDate?: string
    createdAt: string
  }>
}